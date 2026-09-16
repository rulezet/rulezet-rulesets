rule TTP_XOR_QUAD_CurrentVersionRun_bba2 {
  strings:
    $key_bba2 = { e8 cd [2] cc c3 [2] e7 ef [2] c9 cd [2] dd d6 [2] d2 cc [2] cc d1 [2] ce d0 [2] d5 d6 [2] c9 d1 [2] d5 fe }

  condition:
    any of them
}