rule TTP_XOR_QUAD_CurrentVersionRun_b1e2 {
  strings:
    $key_b1e2 = { e2 8d [2] c6 83 [2] ed af [2] c3 8d [2] d7 96 [2] d8 8c [2] c6 91 [2] c4 90 [2] df 96 [2] c3 91 [2] df be }

  condition:
    any of them
}