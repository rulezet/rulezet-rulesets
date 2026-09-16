rule TTP_XOR_QUAD_CurrentVersionRun_acb6 {
  strings:
    $key_acb6 = { ff d9 [2] db d7 [2] f0 fb [2] de d9 [2] ca c2 [2] c5 d8 [2] db c5 [2] d9 c4 [2] c2 c2 [2] de c5 [2] c2 ea }

  condition:
    any of them
}