rule TTP_XOR_QUAD_CurrentVersionRun_a0e2 {
  strings:
    $key_a0e2 = { f3 8d [2] d7 83 [2] fc af [2] d2 8d [2] c6 96 [2] c9 8c [2] d7 91 [2] d5 90 [2] ce 96 [2] d2 91 [2] ce be }

  condition:
    any of them
}