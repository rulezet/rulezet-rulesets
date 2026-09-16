rule TTP_XOR_QUAD_CurrentVersionRun_bf7e {
  strings:
    $key_bf7e = { ec 11 [2] c8 1f [2] e3 33 [2] cd 11 [2] d9 0a [2] d6 10 [2] c8 0d [2] ca 0c [2] d1 0a [2] cd 0d [2] d1 22 }

  condition:
    any of them
}