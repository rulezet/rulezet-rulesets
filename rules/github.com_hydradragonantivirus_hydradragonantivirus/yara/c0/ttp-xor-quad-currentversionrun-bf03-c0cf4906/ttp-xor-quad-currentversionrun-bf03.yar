rule TTP_XOR_QUAD_CurrentVersionRun_bf03 {
  strings:
    $key_bf03 = { ec 6c [2] c8 62 [2] e3 4e [2] cd 6c [2] d9 77 [2] d6 6d [2] c8 70 [2] ca 71 [2] d1 77 [2] cd 70 [2] d1 5f }

  condition:
    any of them
}