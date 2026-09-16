rule TTP_XOR_QUAD_CurrentVersionRun_06b4 {
  strings:
    $key_06b4 = { 55 db [2] 71 d5 [2] 5a f9 [2] 74 db [2] 60 c0 [2] 6f da [2] 71 c7 [2] 73 c6 [2] 68 c0 [2] 74 c7 [2] 68 e8 }

  condition:
    any of them
}