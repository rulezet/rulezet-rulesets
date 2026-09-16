rule TTP_XOR_QUAD_CurrentVersionRun_631b {
  strings:
    $key_631b = { 30 74 [2] 14 7a [2] 3f 56 [2] 11 74 [2] 05 6f [2] 0a 75 [2] 14 68 [2] 16 69 [2] 0d 6f [2] 11 68 [2] 0d 47 }

  condition:
    any of them
}