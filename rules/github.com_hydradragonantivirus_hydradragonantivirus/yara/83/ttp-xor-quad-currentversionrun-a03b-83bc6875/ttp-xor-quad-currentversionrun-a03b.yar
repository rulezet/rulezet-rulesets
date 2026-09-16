rule TTP_XOR_QUAD_CurrentVersionRun_a03b {
  strings:
    $key_a03b = { f3 54 [2] d7 5a [2] fc 76 [2] d2 54 [2] c6 4f [2] c9 55 [2] d7 48 [2] d5 49 [2] ce 4f [2] d2 48 [2] ce 67 }

  condition:
    any of them
}