rule TTP_XOR_QUAD_CurrentVersionRun_a37e {
  strings:
    $key_a37e = { f0 11 [2] d4 1f [2] ff 33 [2] d1 11 [2] c5 0a [2] ca 10 [2] d4 0d [2] d6 0c [2] cd 0a [2] d1 0d [2] cd 22 }

  condition:
    any of them
}