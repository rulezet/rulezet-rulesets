rule TTP_XOR_QUAD_CurrentVersionRun_a330 {
  strings:
    $key_a330 = { f0 5f [2] d4 51 [2] ff 7d [2] d1 5f [2] c5 44 [2] ca 5e [2] d4 43 [2] d6 42 [2] cd 44 [2] d1 43 [2] cd 6c }

  condition:
    any of them
}