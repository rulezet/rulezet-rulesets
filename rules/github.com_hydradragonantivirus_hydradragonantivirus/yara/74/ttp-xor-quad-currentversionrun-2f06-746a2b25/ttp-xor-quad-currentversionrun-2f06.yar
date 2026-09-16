rule TTP_XOR_QUAD_CurrentVersionRun_2f06 {
  strings:
    $key_2f06 = { 7c 69 [2] 58 67 [2] 73 4b [2] 5d 69 [2] 49 72 [2] 46 68 [2] 58 75 [2] 5a 74 [2] 41 72 [2] 5d 75 [2] 41 5a }

  condition:
    any of them
}