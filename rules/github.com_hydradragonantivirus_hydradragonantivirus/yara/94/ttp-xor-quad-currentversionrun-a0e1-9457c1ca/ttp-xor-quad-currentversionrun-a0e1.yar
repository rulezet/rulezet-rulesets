rule TTP_XOR_QUAD_CurrentVersionRun_a0e1 {
  strings:
    $key_a0e1 = { f3 8e [2] d7 80 [2] fc ac [2] d2 8e [2] c6 95 [2] c9 8f [2] d7 92 [2] d5 93 [2] ce 95 [2] d2 92 [2] ce bd }

  condition:
    any of them
}