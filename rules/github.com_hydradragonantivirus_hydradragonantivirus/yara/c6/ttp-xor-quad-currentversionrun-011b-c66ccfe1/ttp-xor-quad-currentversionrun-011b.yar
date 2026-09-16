rule TTP_XOR_QUAD_CurrentVersionRun_011b {
  strings:
    $key_011b = { 52 74 [2] 76 7a [2] 5d 56 [2] 73 74 [2] 67 6f [2] 68 75 [2] 76 68 [2] 74 69 [2] 6f 6f [2] 73 68 [2] 6f 47 }

  condition:
    any of them
}