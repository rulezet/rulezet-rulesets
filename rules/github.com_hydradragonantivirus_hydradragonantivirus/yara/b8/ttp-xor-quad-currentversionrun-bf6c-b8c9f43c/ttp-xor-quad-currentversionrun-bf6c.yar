rule TTP_XOR_QUAD_CurrentVersionRun_bf6c {
  strings:
    $key_bf6c = { ec 03 [2] c8 0d [2] e3 21 [2] cd 03 [2] d9 18 [2] d6 02 [2] c8 1f [2] ca 1e [2] d1 18 [2] cd 1f [2] d1 30 }

  condition:
    any of them
}