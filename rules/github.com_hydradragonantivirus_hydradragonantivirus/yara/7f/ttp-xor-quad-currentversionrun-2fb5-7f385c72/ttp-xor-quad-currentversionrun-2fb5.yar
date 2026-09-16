rule TTP_XOR_QUAD_CurrentVersionRun_2fb5 {
  strings:
    $key_2fb5 = { 7c da [2] 58 d4 [2] 73 f8 [2] 5d da [2] 49 c1 [2] 46 db [2] 58 c6 [2] 5a c7 [2] 41 c1 [2] 5d c6 [2] 41 e9 }

  condition:
    any of them
}