rule TTP_XOR_QUAD_CurrentVersionRun_03b4 {
  strings:
    $key_03b4 = { 50 db [2] 74 d5 [2] 5f f9 [2] 71 db [2] 65 c0 [2] 6a da [2] 74 c7 [2] 76 c6 [2] 6d c0 [2] 71 c7 [2] 6d e8 }

  condition:
    any of them
}