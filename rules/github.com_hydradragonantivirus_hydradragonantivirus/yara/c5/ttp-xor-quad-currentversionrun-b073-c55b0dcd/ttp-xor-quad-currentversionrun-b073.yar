rule TTP_XOR_QUAD_CurrentVersionRun_b073 {
  strings:
    $key_b073 = { e3 1c [2] c7 12 [2] ec 3e [2] c2 1c [2] d6 07 [2] d9 1d [2] c7 00 [2] c5 01 [2] de 07 [2] c2 00 [2] de 2f }

  condition:
    any of them
}