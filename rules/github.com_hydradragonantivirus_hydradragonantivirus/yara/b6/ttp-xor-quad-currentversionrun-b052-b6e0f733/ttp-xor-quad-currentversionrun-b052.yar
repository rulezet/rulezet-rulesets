rule TTP_XOR_QUAD_CurrentVersionRun_b052 {
  strings:
    $key_b052 = { e3 3d [2] c7 33 [2] ec 1f [2] c2 3d [2] d6 26 [2] d9 3c [2] c7 21 [2] c5 20 [2] de 26 [2] c2 21 [2] de 0e }

  condition:
    any of them
}