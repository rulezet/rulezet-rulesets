rule TTP_XOR_QUAD_CurrentVersionRun_a37c {
  strings:
    $key_a37c = { f0 13 [2] d4 1d [2] ff 31 [2] d1 13 [2] c5 08 [2] ca 12 [2] d4 0f [2] d6 0e [2] cd 08 [2] d1 0f [2] cd 20 }

  condition:
    any of them
}