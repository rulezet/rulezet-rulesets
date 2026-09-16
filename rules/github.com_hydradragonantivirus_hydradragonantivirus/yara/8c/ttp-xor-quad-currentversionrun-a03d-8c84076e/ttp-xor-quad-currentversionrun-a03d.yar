rule TTP_XOR_QUAD_CurrentVersionRun_a03d {
  strings:
    $key_a03d = { f3 52 [2] d7 5c [2] fc 70 [2] d2 52 [2] c6 49 [2] c9 53 [2] d7 4e [2] d5 4f [2] ce 49 [2] d2 4e [2] ce 61 }

  condition:
    any of them
}