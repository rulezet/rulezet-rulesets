rule TTP_XOR_QUAD_CurrentVersionRun_bf23 {
  strings:
    $key_bf23 = { ec 4c [2] c8 42 [2] e3 6e [2] cd 4c [2] d9 57 [2] d6 4d [2] c8 50 [2] ca 51 [2] d1 57 [2] cd 50 [2] d1 7f }

  condition:
    any of them
}