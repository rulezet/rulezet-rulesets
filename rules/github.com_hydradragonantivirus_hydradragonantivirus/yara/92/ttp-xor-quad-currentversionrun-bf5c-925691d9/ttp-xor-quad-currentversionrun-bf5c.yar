rule TTP_XOR_QUAD_CurrentVersionRun_bf5c {
  strings:
    $key_bf5c = { ec 33 [2] c8 3d [2] e3 11 [2] cd 33 [2] d9 28 [2] d6 32 [2] c8 2f [2] ca 2e [2] d1 28 [2] cd 2f [2] d1 00 }

  condition:
    any of them
}