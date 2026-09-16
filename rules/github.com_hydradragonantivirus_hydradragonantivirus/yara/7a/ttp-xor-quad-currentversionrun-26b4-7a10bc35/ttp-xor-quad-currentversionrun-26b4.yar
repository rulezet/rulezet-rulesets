rule TTP_XOR_QUAD_CurrentVersionRun_26b4 {
  strings:
    $key_26b4 = { 75 db [2] 51 d5 [2] 7a f9 [2] 54 db [2] 40 c0 [2] 4f da [2] 51 c7 [2] 53 c6 [2] 48 c0 [2] 54 c7 [2] 48 e8 }

  condition:
    any of them
}