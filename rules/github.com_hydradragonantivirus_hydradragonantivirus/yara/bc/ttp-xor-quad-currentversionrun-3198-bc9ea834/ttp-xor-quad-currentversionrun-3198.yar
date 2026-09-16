rule TTP_XOR_QUAD_CurrentVersionRun_3198 {
  strings:
    $key_3198 = { 62 f7 [2] 46 f9 [2] 6d d5 [2] 43 f7 [2] 57 ec [2] 58 f6 [2] 46 eb [2] 44 ea [2] 5f ec [2] 43 eb [2] 5f c4 }

  condition:
    any of them
}