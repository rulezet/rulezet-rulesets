rule TTP_XOR_QUAD_CurrentVersionRun_2106 {
  strings:
    $key_2106 = { 72 69 [2] 56 67 [2] 7d 4b [2] 53 69 [2] 47 72 [2] 48 68 [2] 56 75 [2] 54 74 [2] 4f 72 [2] 53 75 [2] 4f 5a }

  condition:
    any of them
}