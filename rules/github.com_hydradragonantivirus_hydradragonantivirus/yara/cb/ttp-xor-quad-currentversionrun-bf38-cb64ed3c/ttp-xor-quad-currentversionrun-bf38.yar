rule TTP_XOR_QUAD_CurrentVersionRun_bf38 {
  strings:
    $key_bf38 = { ec 57 [2] c8 59 [2] e3 75 [2] cd 57 [2] d9 4c [2] d6 56 [2] c8 4b [2] ca 4a [2] d1 4c [2] cd 4b [2] d1 64 }

  condition:
    any of them
}