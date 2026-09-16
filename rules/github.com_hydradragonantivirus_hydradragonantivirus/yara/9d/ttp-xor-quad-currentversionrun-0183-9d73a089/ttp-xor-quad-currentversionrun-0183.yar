rule TTP_XOR_QUAD_CurrentVersionRun_0183 {
  strings:
    $key_0183 = { 52 ec [2] 76 e2 [2] 5d ce [2] 73 ec [2] 67 f7 [2] 68 ed [2] 76 f0 [2] 74 f1 [2] 6f f7 [2] 73 f0 [2] 6f df }

  condition:
    any of them
}