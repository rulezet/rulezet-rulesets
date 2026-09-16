rule TTP_XOR_QUAD_CurrentVersionRun_bf7c {
  strings:
    $key_bf7c = { ec 13 [2] c8 1d [2] e3 31 [2] cd 13 [2] d9 08 [2] d6 12 [2] c8 0f [2] ca 0e [2] d1 08 [2] cd 0f [2] d1 20 }

  condition:
    any of them
}