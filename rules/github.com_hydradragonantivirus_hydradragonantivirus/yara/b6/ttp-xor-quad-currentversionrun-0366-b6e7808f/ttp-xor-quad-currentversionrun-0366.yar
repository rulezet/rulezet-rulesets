rule TTP_XOR_QUAD_CurrentVersionRun_0366 {
  strings:
    $key_0366 = { 50 09 [2] 74 07 [2] 5f 2b [2] 71 09 [2] 65 12 [2] 6a 08 [2] 74 15 [2] 76 14 [2] 6d 12 [2] 71 15 [2] 6d 3a }

  condition:
    any of them
}