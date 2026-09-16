rule TTP_XOR_QUAD_CurrentVersionRun_a380 {
  strings:
    $key_a380 = { f0 ef [2] d4 e1 [2] ff cd [2] d1 ef [2] c5 f4 [2] ca ee [2] d4 f3 [2] d6 f2 [2] cd f4 [2] d1 f3 [2] cd dc }

  condition:
    any of them
}