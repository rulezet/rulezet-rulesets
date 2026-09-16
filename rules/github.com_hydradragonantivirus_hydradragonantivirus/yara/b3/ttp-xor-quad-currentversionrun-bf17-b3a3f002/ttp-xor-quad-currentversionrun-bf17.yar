rule TTP_XOR_QUAD_CurrentVersionRun_bf17 {
  strings:
    $key_bf17 = { ec 78 [2] c8 76 [2] e3 5a [2] cd 78 [2] d9 63 [2] d6 79 [2] c8 64 [2] ca 65 [2] d1 63 [2] cd 64 [2] d1 4b }

  condition:
    any of them
}