rule TTP_XOR_QUAD_CurrentVersionRun_bf5a {
  strings:
    $key_bf5a = { ec 35 [2] c8 3b [2] e3 17 [2] cd 35 [2] d9 2e [2] d6 34 [2] c8 29 [2] ca 28 [2] d1 2e [2] cd 29 [2] d1 06 }

  condition:
    any of them
}