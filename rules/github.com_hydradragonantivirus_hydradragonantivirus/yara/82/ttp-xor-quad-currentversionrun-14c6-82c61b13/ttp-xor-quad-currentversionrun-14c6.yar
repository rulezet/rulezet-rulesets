rule TTP_XOR_QUAD_CurrentVersionRun_14c6 {
  strings:
    $key_14c6 = { 47 a9 [2] 63 a7 [2] 48 8b [2] 66 a9 [2] 72 b2 [2] 7d a8 [2] 63 b5 [2] 61 b4 [2] 7a b2 [2] 66 b5 [2] 7a 9a }

  condition:
    any of them
}