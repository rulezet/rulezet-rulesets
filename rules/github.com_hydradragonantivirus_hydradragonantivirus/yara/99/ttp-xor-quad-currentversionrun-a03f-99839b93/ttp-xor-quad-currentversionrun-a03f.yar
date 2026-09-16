rule TTP_XOR_QUAD_CurrentVersionRun_a03f {
  strings:
    $key_a03f = { f3 50 [2] d7 5e [2] fc 72 [2] d2 50 [2] c6 4b [2] c9 51 [2] d7 4c [2] d5 4d [2] ce 4b [2] d2 4c [2] ce 63 }

  condition:
    any of them
}