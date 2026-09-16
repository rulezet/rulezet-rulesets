rule TTP_XOR_QUAD_CurrentVersionRun_a350 {
  strings:
    $key_a350 = { f0 3f [2] d4 31 [2] ff 1d [2] d1 3f [2] c5 24 [2] ca 3e [2] d4 23 [2] d6 22 [2] cd 24 [2] d1 23 [2] cd 0c }

  condition:
    any of them
}