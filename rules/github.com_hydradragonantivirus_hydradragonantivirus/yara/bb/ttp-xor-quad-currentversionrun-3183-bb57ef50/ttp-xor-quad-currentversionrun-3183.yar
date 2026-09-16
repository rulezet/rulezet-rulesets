rule TTP_XOR_QUAD_CurrentVersionRun_3183 {
  strings:
    $key_3183 = { 62 ec [2] 46 e2 [2] 6d ce [2] 43 ec [2] 57 f7 [2] 58 ed [2] 46 f0 [2] 44 f1 [2] 5f f7 [2] 43 f0 [2] 5f df }

  condition:
    any of them
}