rule TTP_XOR_QUAD_CurrentVersionRun_5106 {
  strings:
    $key_5106 = { 02 69 [2] 26 67 [2] 0d 4b [2] 23 69 [2] 37 72 [2] 38 68 [2] 26 75 [2] 24 74 [2] 3f 72 [2] 23 75 [2] 3f 5a }

  condition:
    any of them
}