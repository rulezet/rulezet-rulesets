rule TTP_XOR_QUAD_CurrentVersionRun_b05c {
  strings:
    $key_b05c = { e3 33 [2] c7 3d [2] ec 11 [2] c2 33 [2] d6 28 [2] d9 32 [2] c7 2f [2] c5 2e [2] de 28 [2] c2 2f [2] de 00 }

  condition:
    any of them
}