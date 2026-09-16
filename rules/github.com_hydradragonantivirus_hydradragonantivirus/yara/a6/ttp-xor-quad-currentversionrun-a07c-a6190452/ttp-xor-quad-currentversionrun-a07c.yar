rule TTP_XOR_QUAD_CurrentVersionRun_a07c {
  strings:
    $key_a07c = { f3 13 [2] d7 1d [2] fc 31 [2] d2 13 [2] c6 08 [2] c9 12 [2] d7 0f [2] d5 0e [2] ce 08 [2] d2 0f [2] ce 20 }

  condition:
    any of them
}