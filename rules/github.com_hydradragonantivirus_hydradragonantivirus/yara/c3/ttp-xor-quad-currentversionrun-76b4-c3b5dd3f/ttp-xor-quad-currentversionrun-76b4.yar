rule TTP_XOR_QUAD_CurrentVersionRun_76b4 {
  strings:
    $key_76b4 = { 25 db [2] 01 d5 [2] 2a f9 [2] 04 db [2] 10 c0 [2] 1f da [2] 01 c7 [2] 03 c6 [2] 18 c0 [2] 04 c7 [2] 18 e8 }

  condition:
    any of them
}