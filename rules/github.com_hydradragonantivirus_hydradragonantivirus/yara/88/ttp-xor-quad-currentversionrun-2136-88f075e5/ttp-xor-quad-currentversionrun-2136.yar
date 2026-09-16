rule TTP_XOR_QUAD_CurrentVersionRun_2136 {
  strings:
    $key_2136 = { 72 59 [2] 56 57 [2] 7d 7b [2] 53 59 [2] 47 42 [2] 48 58 [2] 56 45 [2] 54 44 [2] 4f 42 [2] 53 45 [2] 4f 6a }

  condition:
    any of them
}