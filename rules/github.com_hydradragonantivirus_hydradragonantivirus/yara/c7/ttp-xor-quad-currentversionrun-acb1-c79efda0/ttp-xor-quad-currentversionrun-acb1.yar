rule TTP_XOR_QUAD_CurrentVersionRun_acb1 {
  strings:
    $key_acb1 = { ff de [2] db d0 [2] f0 fc [2] de de [2] ca c5 [2] c5 df [2] db c2 [2] d9 c3 [2] c2 c5 [2] de c2 [2] c2 ed }

  condition:
    any of them
}