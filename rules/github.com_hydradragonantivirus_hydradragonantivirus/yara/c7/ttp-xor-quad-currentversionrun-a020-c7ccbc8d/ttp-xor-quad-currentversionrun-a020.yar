rule TTP_XOR_QUAD_CurrentVersionRun_a020 {
  strings:
    $key_a020 = { f3 4f [2] d7 41 [2] fc 6d [2] d2 4f [2] c6 54 [2] c9 4e [2] d7 53 [2] d5 52 [2] ce 54 [2] d2 53 [2] ce 7c }

  condition:
    any of them
}