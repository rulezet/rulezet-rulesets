rule TTP_XOR_QUAD_CurrentVersionRun_17b5 {
  strings:
    $key_17b5 = { 44 da [2] 60 d4 [2] 4b f8 [2] 65 da [2] 71 c1 [2] 7e db [2] 60 c6 [2] 62 c7 [2] 79 c1 [2] 65 c6 [2] 79 e9 }

  condition:
    any of them
}