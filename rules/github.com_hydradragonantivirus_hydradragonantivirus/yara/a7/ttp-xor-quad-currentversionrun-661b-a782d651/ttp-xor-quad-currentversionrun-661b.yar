rule TTP_XOR_QUAD_CurrentVersionRun_661b {
  strings:
    $key_661b = { 35 74 [2] 11 7a [2] 3a 56 [2] 14 74 [2] 00 6f [2] 0f 75 [2] 11 68 [2] 13 69 [2] 08 6f [2] 14 68 [2] 08 47 }

  condition:
    any of them
}