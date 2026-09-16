rule TTP_XOR_QUAD_CurrentVersionRun_a071 {
  strings:
    $key_a071 = { f3 1e [2] d7 10 [2] fc 3c [2] d2 1e [2] c6 05 [2] c9 1f [2] d7 02 [2] d5 03 [2] ce 05 [2] d2 02 [2] ce 2d }

  condition:
    any of them
}