rule TTP_XOR_QUAD_CurrentVersionRun_6406 {
  strings:
    $key_6406 = { 37 69 [2] 13 67 [2] 38 4b [2] 16 69 [2] 02 72 [2] 0d 68 [2] 13 75 [2] 11 74 [2] 0a 72 [2] 16 75 [2] 0a 5a }

  condition:
    any of them
}