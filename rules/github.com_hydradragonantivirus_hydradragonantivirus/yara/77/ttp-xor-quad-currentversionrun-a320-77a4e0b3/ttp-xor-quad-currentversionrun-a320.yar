rule TTP_XOR_QUAD_CurrentVersionRun_a320 {
  strings:
    $key_a320 = { f0 4f [2] d4 41 [2] ff 6d [2] d1 4f [2] c5 54 [2] ca 4e [2] d4 53 [2] d6 52 [2] cd 54 [2] d1 53 [2] cd 7c }

  condition:
    any of them
}