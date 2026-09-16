rule TTP_XOR_QUAD_CurrentVersionRun_bf13 {
  strings:
    $key_bf13 = { ec 7c [2] c8 72 [2] e3 5e [2] cd 7c [2] d9 67 [2] d6 7d [2] c8 60 [2] ca 61 [2] d1 67 [2] cd 60 [2] d1 4f }

  condition:
    any of them
}