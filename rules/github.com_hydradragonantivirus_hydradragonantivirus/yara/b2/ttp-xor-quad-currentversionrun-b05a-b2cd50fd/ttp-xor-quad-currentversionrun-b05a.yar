rule TTP_XOR_QUAD_CurrentVersionRun_b05a {
  strings:
    $key_b05a = { e3 35 [2] c7 3b [2] ec 17 [2] c2 35 [2] d6 2e [2] d9 34 [2] c7 29 [2] c5 28 [2] de 2e [2] c2 29 [2] de 06 }

  condition:
    any of them
}