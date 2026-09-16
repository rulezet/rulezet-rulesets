rule TTP_XOR_QUAD_CurrentVersionRun_bf6e {
  strings:
    $key_bf6e = { ec 01 [2] c8 0f [2] e3 23 [2] cd 01 [2] d9 1a [2] d6 00 [2] c8 1d [2] ca 1c [2] d1 1a [2] cd 1d [2] d1 32 }

  condition:
    any of them
}