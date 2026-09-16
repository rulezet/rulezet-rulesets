rule TTP_XOR_QUAD_CurrentVersionRun_1b62 {
  strings:
    $key_1b62 = { 48 0d [2] 6c 03 [2] 47 2f [2] 69 0d [2] 7d 16 [2] 72 0c [2] 6c 11 [2] 6e 10 [2] 75 16 [2] 69 11 [2] 75 3e }

  condition:
    any of them
}