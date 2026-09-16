rule TTP_XOR_QUAD_CurrentVersionRun_1198 {
  strings:
    $key_1198 = { 42 f7 [2] 66 f9 [2] 4d d5 [2] 63 f7 [2] 77 ec [2] 78 f6 [2] 66 eb [2] 64 ea [2] 7f ec [2] 63 eb [2] 7f c4 }

  condition:
    any of them
}