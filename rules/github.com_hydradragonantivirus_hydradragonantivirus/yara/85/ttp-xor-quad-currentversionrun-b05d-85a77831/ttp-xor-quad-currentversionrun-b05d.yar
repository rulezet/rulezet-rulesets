rule TTP_XOR_QUAD_CurrentVersionRun_b05d {
  strings:
    $key_b05d = { e3 32 [2] c7 3c [2] ec 10 [2] c2 32 [2] d6 29 [2] d9 33 [2] c7 2e [2] c5 2f [2] de 29 [2] c2 2e [2] de 01 }

  condition:
    any of them
}