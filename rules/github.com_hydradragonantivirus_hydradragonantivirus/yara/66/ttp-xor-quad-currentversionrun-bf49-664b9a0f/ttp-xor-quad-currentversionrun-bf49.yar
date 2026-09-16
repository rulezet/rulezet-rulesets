rule TTP_XOR_QUAD_CurrentVersionRun_bf49 {
  strings:
    $key_bf49 = { ec 26 [2] c8 28 [2] e3 04 [2] cd 26 [2] d9 3d [2] d6 27 [2] c8 3a [2] ca 3b [2] d1 3d [2] cd 3a [2] d1 15 }

  condition:
    any of them
}