rule TTP_XOR_QUAD_CurrentVersionRun_a00c {
  strings:
    $key_a00c = { f3 63 [2] d7 6d [2] fc 41 [2] d2 63 [2] c6 78 [2] c9 62 [2] d7 7f [2] d5 7e [2] ce 78 [2] d2 7f [2] ce 50 }

  condition:
    any of them
}