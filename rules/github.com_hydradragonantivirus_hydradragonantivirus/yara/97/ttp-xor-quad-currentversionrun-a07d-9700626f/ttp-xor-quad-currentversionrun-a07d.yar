rule TTP_XOR_QUAD_CurrentVersionRun_a07d {
  strings:
    $key_a07d = { f3 12 [2] d7 1c [2] fc 30 [2] d2 12 [2] c6 09 [2] c9 13 [2] d7 0e [2] d5 0f [2] ce 09 [2] d2 0e [2] ce 21 }

  condition:
    any of them
}