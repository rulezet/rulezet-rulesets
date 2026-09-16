rule TTP_XOR_QUAD_CurrentVersionRun_a011 {
  strings:
    $key_a011 = { f3 7e [2] d7 70 [2] fc 5c [2] d2 7e [2] c6 65 [2] c9 7f [2] d7 62 [2] d5 63 [2] ce 65 [2] d2 62 [2] ce 4d }

  condition:
    any of them
}