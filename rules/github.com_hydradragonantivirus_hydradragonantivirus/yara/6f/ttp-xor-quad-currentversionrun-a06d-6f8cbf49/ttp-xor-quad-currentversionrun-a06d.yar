rule TTP_XOR_QUAD_CurrentVersionRun_a06d {
  strings:
    $key_a06d = { f3 02 [2] d7 0c [2] fc 20 [2] d2 02 [2] c6 19 [2] c9 03 [2] d7 1e [2] d5 1f [2] ce 19 [2] d2 1e [2] ce 31 }

  condition:
    any of them
}