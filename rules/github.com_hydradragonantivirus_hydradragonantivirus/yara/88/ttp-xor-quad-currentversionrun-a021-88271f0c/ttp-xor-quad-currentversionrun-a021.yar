rule TTP_XOR_QUAD_CurrentVersionRun_a021 {
  strings:
    $key_a021 = { f3 4e [2] d7 40 [2] fc 6c [2] d2 4e [2] c6 55 [2] c9 4f [2] d7 52 [2] d5 53 [2] ce 55 [2] d2 52 [2] ce 7d }

  condition:
    any of them
}