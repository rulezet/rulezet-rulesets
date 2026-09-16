rule TTP_XOR_QUAD_CurrentVersionRun_bf63 {
  strings:
    $key_bf63 = { ec 0c [2] c8 02 [2] e3 2e [2] cd 0c [2] d9 17 [2] d6 0d [2] c8 10 [2] ca 11 [2] d1 17 [2] cd 10 [2] d1 3f }

  condition:
    any of them
}