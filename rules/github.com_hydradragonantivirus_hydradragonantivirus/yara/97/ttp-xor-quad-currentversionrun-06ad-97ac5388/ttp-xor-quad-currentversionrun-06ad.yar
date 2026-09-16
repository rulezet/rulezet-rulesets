rule TTP_XOR_QUAD_CurrentVersionRun_06ad {
  strings:
    $key_06ad = { 55 c2 [2] 71 cc [2] 5a e0 [2] 74 c2 [2] 60 d9 [2] 6f c3 [2] 71 de [2] 73 df [2] 68 d9 [2] 74 de [2] 68 f1 }

  condition:
    any of them
}