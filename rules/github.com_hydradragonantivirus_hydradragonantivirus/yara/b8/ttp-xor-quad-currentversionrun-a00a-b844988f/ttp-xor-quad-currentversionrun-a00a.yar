rule TTP_XOR_QUAD_CurrentVersionRun_a00a {
  strings:
    $key_a00a = { f3 65 [2] d7 6b [2] fc 47 [2] d2 65 [2] c6 7e [2] c9 64 [2] d7 79 [2] d5 78 [2] ce 7e [2] d2 79 [2] ce 56 }

  condition:
    any of them
}