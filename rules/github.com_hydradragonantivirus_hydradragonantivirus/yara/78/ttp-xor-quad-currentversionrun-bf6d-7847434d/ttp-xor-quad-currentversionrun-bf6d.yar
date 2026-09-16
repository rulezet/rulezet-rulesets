rule TTP_XOR_QUAD_CurrentVersionRun_bf6d {
  strings:
    $key_bf6d = { ec 02 [2] c8 0c [2] e3 20 [2] cd 02 [2] d9 19 [2] d6 03 [2] c8 1e [2] ca 1f [2] d1 19 [2] cd 1e [2] d1 31 }

  condition:
    any of them
}