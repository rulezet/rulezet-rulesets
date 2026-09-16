rule TTP_XOR_QUAD_CurrentVersionRun_a30b {
  strings:
    $key_a30b = { f0 64 [2] d4 6a [2] ff 46 [2] d1 64 [2] c5 7f [2] ca 65 [2] d4 78 [2] d6 79 [2] cd 7f [2] d1 78 [2] cd 57 }

  condition:
    any of them
}