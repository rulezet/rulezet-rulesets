rule TTP_XOR_QUAD_CurrentVersionRun_1f06 {
  strings:
    $key_1f06 = { 4c 69 [2] 68 67 [2] 43 4b [2] 6d 69 [2] 79 72 [2] 76 68 [2] 68 75 [2] 6a 74 [2] 71 72 [2] 6d 75 [2] 71 5a }

  condition:
    any of them
}