rule TTP_XOR_QUAD_CurrentVersionRun_1006 {
  strings:
    $key_1006 = { 43 69 [2] 67 67 [2] 4c 4b [2] 62 69 [2] 76 72 [2] 79 68 [2] 67 75 [2] 65 74 [2] 7e 72 [2] 62 75 [2] 7e 5a }

  condition:
    any of them
}