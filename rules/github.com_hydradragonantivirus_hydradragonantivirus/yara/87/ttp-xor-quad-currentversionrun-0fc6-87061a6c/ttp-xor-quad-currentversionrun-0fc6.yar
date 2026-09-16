rule TTP_XOR_QUAD_CurrentVersionRun_0fc6 {
  strings:
    $key_0fc6 = { 5c a9 [2] 78 a7 [2] 53 8b [2] 7d a9 [2] 69 b2 [2] 66 a8 [2] 78 b5 [2] 7a b4 [2] 61 b2 [2] 7d b5 [2] 61 9a }

  condition:
    any of them
}