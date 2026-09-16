rule TTP_XOR_QUAD_CurrentVersionRun_769a {
  strings:
    $key_769a = { 25 f5 [2] 01 fb [2] 2a d7 [2] 04 f5 [2] 10 ee [2] 1f f4 [2] 01 e9 [2] 03 e8 [2] 18 ee [2] 04 e9 [2] 18 c6 }

  condition:
    any of them
}