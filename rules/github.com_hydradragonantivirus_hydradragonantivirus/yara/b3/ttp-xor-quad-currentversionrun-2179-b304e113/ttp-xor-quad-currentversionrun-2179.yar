rule TTP_XOR_QUAD_CurrentVersionRun_2179 {
  strings:
    $key_2179 = { 72 16 [2] 56 18 [2] 7d 34 [2] 53 16 [2] 47 0d [2] 48 17 [2] 56 0a [2] 54 0b [2] 4f 0d [2] 53 0a [2] 4f 25 }

  condition:
    any of them
}