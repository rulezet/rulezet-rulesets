rule TTP_XOR_QUAD_CurrentVersionRun_aca6 {
  strings:
    $key_aca6 = { ff c9 [2] db c7 [2] f0 eb [2] de c9 [2] ca d2 [2] c5 c8 [2] db d5 [2] d9 d4 [2] c2 d2 [2] de d5 [2] c2 fa }

  condition:
    any of them
}