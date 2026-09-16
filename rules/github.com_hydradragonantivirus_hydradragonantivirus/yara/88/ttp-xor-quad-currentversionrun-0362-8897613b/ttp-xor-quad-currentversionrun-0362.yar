rule TTP_XOR_QUAD_CurrentVersionRun_0362 {
  strings:
    $key_0362 = { 50 0d [2] 74 03 [2] 5f 2f [2] 71 0d [2] 65 16 [2] 6a 0c [2] 74 11 [2] 76 10 [2] 6d 16 [2] 71 11 [2] 6d 3e }

  condition:
    any of them
}