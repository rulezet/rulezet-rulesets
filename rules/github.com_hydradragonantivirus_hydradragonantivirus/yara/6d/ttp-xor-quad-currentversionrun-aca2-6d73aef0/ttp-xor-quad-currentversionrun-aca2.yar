rule TTP_XOR_QUAD_CurrentVersionRun_aca2 {
  strings:
    $key_aca2 = { ff cd [2] db c3 [2] f0 ef [2] de cd [2] ca d6 [2] c5 cc [2] db d1 [2] d9 d0 [2] c2 d6 [2] de d1 [2] c2 fe }

  condition:
    any of them
}