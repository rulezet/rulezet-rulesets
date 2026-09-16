rule TTP_XOR_QUAD_CurrentVersionRun_bf4a {
  strings:
    $key_bf4a = { ec 25 [2] c8 2b [2] e3 07 [2] cd 25 [2] d9 3e [2] d6 24 [2] c8 39 [2] ca 38 [2] d1 3e [2] cd 39 [2] d1 16 }

  condition:
    any of them
}