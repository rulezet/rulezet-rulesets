rule TTP_XOR_QUAD_CurrentVersionRun_7e40 {
  strings:
    $key_7e40 = { 2d 2f [2] 09 21 [2] 22 0d [2] 0c 2f [2] 18 34 [2] 17 2e [2] 09 33 [2] 0b 32 [2] 10 34 [2] 0c 33 [2] 10 1c }

  condition:
    any of them
}