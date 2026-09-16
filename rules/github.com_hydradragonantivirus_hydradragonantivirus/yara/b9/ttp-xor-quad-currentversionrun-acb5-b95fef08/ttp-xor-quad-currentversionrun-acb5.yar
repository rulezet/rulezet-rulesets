rule TTP_XOR_QUAD_CurrentVersionRun_acb5 {
  strings:
    $key_acb5 = { ff da [2] db d4 [2] f0 f8 [2] de da [2] ca c1 [2] c5 db [2] db c6 [2] d9 c7 [2] c2 c1 [2] de c6 [2] c2 e9 }

  condition:
    any of them
}