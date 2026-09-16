rule TTP_XOR_QUAD_CurrentVersionRun_b0a2 {
  strings:
    $key_b0a2 = { e3 cd [2] c7 c3 [2] ec ef [2] c2 cd [2] d6 d6 [2] d9 cc [2] c7 d1 [2] c5 d0 [2] de d6 [2] c2 d1 [2] de fe }

  condition:
    any of them
}