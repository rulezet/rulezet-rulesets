rule TTP_XOR_QUAD_CurrentVersionRun_a7e1 {
  strings:
    $key_a7e1 = { f4 8e [2] d0 80 [2] fb ac [2] d5 8e [2] c1 95 [2] ce 8f [2] d0 92 [2] d2 93 [2] c9 95 [2] d5 92 [2] c9 bd }

  condition:
    any of them
}