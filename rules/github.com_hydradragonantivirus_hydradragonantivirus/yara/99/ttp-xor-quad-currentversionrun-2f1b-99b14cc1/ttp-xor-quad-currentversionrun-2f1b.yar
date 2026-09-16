rule TTP_XOR_QUAD_CurrentVersionRun_2f1b {
  strings:
    $key_2f1b = { 7c 74 [2] 58 7a [2] 73 56 [2] 5d 74 [2] 49 6f [2] 46 75 [2] 58 68 [2] 5a 69 [2] 41 6f [2] 5d 68 [2] 41 47 }

  condition:
    any of them
}