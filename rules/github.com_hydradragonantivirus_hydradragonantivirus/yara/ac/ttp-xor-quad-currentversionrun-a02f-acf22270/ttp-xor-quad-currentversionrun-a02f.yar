rule TTP_XOR_QUAD_CurrentVersionRun_a02f {
  strings:
    $key_a02f = { f3 40 [2] d7 4e [2] fc 62 [2] d2 40 [2] c6 5b [2] c9 41 [2] d7 5c [2] d5 5d [2] ce 5b [2] d2 5c [2] ce 73 }

  condition:
    any of them
}