rule TTP_XOR_QUAD_CurrentVersionRun_a00f {
  strings:
    $key_a00f = { f3 60 [2] d7 6e [2] fc 42 [2] d2 60 [2] c6 7b [2] c9 61 [2] d7 7c [2] d5 7d [2] ce 7b [2] d2 7c [2] ce 53 }

  condition:
    any of them
}