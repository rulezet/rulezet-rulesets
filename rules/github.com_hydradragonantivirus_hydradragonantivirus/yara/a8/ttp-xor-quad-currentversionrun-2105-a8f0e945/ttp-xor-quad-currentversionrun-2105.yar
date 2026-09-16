rule TTP_XOR_QUAD_CurrentVersionRun_2105 {
  strings:
    $key_2105 = { 72 6a [2] 56 64 [2] 7d 48 [2] 53 6a [2] 47 71 [2] 48 6b [2] 56 76 [2] 54 77 [2] 4f 71 [2] 53 76 [2] 4f 59 }

  condition:
    any of them
}