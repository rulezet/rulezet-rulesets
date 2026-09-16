rule TTP_XOR_QUAD_CurrentVersionRun_7e62 {
  strings:
    $key_7e62 = { 2d 0d [2] 09 03 [2] 22 2f [2] 0c 0d [2] 18 16 [2] 17 0c [2] 09 11 [2] 0b 10 [2] 10 16 [2] 0c 11 [2] 10 3e }

  condition:
    any of them
}