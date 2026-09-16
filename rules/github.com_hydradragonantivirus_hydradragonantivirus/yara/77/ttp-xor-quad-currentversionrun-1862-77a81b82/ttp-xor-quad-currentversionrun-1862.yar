rule TTP_XOR_QUAD_CurrentVersionRun_1862 {
  strings:
    $key_1862 = { 4b 0d [2] 6f 03 [2] 44 2f [2] 6a 0d [2] 7e 16 [2] 71 0c [2] 6f 11 [2] 6d 10 [2] 76 16 [2] 6a 11 [2] 76 3e }

  condition:
    any of them
}