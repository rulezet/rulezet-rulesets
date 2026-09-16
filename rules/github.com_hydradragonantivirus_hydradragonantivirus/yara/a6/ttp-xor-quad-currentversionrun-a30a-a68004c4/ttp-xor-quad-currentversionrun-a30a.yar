rule TTP_XOR_QUAD_CurrentVersionRun_a30a {
  strings:
    $key_a30a = { f0 65 [2] d4 6b [2] ff 47 [2] d1 65 [2] c5 7e [2] ca 64 [2] d4 79 [2] d6 78 [2] cd 7e [2] d1 79 [2] cd 56 }

  condition:
    any of them
}