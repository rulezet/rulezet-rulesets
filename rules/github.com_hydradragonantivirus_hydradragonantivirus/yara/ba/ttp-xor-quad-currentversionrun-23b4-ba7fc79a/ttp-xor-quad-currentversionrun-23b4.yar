rule TTP_XOR_QUAD_CurrentVersionRun_23b4 {
  strings:
    $key_23b4 = { 70 db [2] 54 d5 [2] 7f f9 [2] 51 db [2] 45 c0 [2] 4a da [2] 54 c7 [2] 56 c6 [2] 4d c0 [2] 51 c7 [2] 4d e8 }

  condition:
    any of them
}