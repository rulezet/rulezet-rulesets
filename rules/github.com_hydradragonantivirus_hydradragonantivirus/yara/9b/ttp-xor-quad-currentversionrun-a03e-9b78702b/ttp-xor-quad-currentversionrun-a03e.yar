rule TTP_XOR_QUAD_CurrentVersionRun_a03e {
  strings:
    $key_a03e = { f3 51 [2] d7 5f [2] fc 73 [2] d2 51 [2] c6 4a [2] c9 50 [2] d7 4d [2] d5 4c [2] ce 4a [2] d2 4d [2] ce 62 }

  condition:
    any of them
}