rule TTP_XOR_QUAD_CurrentVersionRun_a3ff {
  strings:
    $key_a3ff = { f0 90 [2] d4 9e [2] ff b2 [2] d1 90 [2] c5 8b [2] ca 91 [2] d4 8c [2] d6 8d [2] cd 8b [2] d1 8c [2] cd a3 }

  condition:
    any of them
}