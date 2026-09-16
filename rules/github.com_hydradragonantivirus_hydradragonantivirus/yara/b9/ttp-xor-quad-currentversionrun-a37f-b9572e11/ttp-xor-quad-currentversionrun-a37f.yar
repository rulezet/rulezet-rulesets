rule TTP_XOR_QUAD_CurrentVersionRun_a37f {
  strings:
    $key_a37f = { f0 10 [2] d4 1e [2] ff 32 [2] d1 10 [2] c5 0b [2] ca 11 [2] d4 0c [2] d6 0d [2] cd 0b [2] d1 0c [2] cd 23 }

  condition:
    any of them
}