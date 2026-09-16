rule TTP_XOR_QUAD_CurrentVersionRun_7b06 {
  strings:
    $key_7b06 = { 28 69 [2] 0c 67 [2] 27 4b [2] 09 69 [2] 1d 72 [2] 12 68 [2] 0c 75 [2] 0e 74 [2] 15 72 [2] 09 75 [2] 15 5a }

  condition:
    any of them
}