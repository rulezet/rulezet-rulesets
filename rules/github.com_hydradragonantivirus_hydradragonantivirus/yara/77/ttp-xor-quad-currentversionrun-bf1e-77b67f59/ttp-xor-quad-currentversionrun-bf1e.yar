rule TTP_XOR_QUAD_CurrentVersionRun_bf1e {
  strings:
    $key_bf1e = { ec 71 [2] c8 7f [2] e3 53 [2] cd 71 [2] d9 6a [2] d6 70 [2] c8 6d [2] ca 6c [2] d1 6a [2] cd 6d [2] d1 42 }

  condition:
    any of them
}