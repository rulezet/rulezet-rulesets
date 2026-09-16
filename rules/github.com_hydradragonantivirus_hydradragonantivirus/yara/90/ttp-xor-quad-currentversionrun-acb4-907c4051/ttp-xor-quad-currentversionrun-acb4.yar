rule TTP_XOR_QUAD_CurrentVersionRun_acb4 {
  strings:
    $key_acb4 = { ff db [2] db d5 [2] f0 f9 [2] de db [2] ca c0 [2] c5 da [2] db c7 [2] d9 c6 [2] c2 c0 [2] de c7 [2] c2 e8 }

  condition:
    any of them
}