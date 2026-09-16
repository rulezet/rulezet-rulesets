rule TTP_XOR_QUAD_CurrentVersionRun_bf6b {
  strings:
    $key_bf6b = { ec 04 [2] c8 0a [2] e3 26 [2] cd 04 [2] d9 1f [2] d6 05 [2] c8 18 [2] ca 19 [2] d1 1f [2] cd 18 [2] d1 37 }

  condition:
    any of them
}