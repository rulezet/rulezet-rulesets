rule TTP_XOR_QUAD_CurrentVersionRun_5698 {
  strings:
    $key_5698 = { 05 f7 [2] 21 f9 [2] 0a d5 [2] 24 f7 [2] 30 ec [2] 3f f6 [2] 21 eb [2] 23 ea [2] 38 ec [2] 24 eb [2] 38 c4 }

  condition:
    any of them
}