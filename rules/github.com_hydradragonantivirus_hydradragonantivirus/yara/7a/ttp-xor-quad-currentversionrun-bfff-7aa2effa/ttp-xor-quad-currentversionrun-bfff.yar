rule TTP_XOR_QUAD_CurrentVersionRun_bfff {
  strings:
    $key_bfff = { ec 90 [2] c8 9e [2] e3 b2 [2] cd 90 [2] d9 8b [2] d6 91 [2] c8 8c [2] ca 8d [2] d1 8b [2] cd 8c [2] d1 a3 }

  condition:
    any of them
}