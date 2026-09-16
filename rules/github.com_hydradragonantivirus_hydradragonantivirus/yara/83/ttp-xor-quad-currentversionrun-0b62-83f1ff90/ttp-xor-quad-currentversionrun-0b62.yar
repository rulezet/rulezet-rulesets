rule TTP_XOR_QUAD_CurrentVersionRun_0b62 {
  strings:
    $key_0b62 = { 58 0d [2] 7c 03 [2] 57 2f [2] 79 0d [2] 6d 16 [2] 62 0c [2] 7c 11 [2] 7e 10 [2] 65 16 [2] 79 11 [2] 65 3e }

  condition:
    any of them
}