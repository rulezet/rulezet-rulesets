rule TTP_XOR_QUAD_CurrentVersionRun_a8a2 {
  strings:
    $key_a8a2 = { fb cd [2] df c3 [2] f4 ef [2] da cd [2] ce d6 [2] c1 cc [2] df d1 [2] dd d0 [2] c6 d6 [2] da d1 [2] c6 fe }

  condition:
    any of them
}