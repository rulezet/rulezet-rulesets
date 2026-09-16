rule TTP_XOR_QUAD_CurrentVersionRun_b00a {
  strings:
    $key_b00a = { e3 65 [2] c7 6b [2] ec 47 [2] c2 65 [2] d6 7e [2] d9 64 [2] c7 79 [2] c5 78 [2] de 7e [2] c2 79 [2] de 56 }

  condition:
    any of them
}