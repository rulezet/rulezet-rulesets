rule TTP_XOR_QUAD_CurrentVersionRun_2306 {
  strings:
    $key_2306 = { 70 69 [2] 54 67 [2] 7f 4b [2] 51 69 [2] 45 72 [2] 4a 68 [2] 54 75 [2] 56 74 [2] 4d 72 [2] 51 75 [2] 4d 5a }

  condition:
    any of them
}