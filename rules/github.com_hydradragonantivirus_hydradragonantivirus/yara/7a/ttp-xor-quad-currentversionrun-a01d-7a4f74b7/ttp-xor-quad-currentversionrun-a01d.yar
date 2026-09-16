rule TTP_XOR_QUAD_CurrentVersionRun_a01d {
  strings:
    $key_a01d = { f3 72 [2] d7 7c [2] fc 50 [2] d2 72 [2] c6 69 [2] c9 73 [2] d7 6e [2] d5 6f [2] ce 69 [2] d2 6e [2] ce 41 }

  condition:
    any of them
}