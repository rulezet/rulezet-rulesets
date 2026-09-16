rule TTP_XOR_QUAD_CurrentVersionRun_4b62 {
  strings:
    $key_4b62 = { 18 0d [2] 3c 03 [2] 17 2f [2] 39 0d [2] 2d 16 [2] 22 0c [2] 3c 11 [2] 3e 10 [2] 25 16 [2] 39 11 [2] 25 3e }

  condition:
    any of them
}