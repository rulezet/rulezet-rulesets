rule TTP_XOR_QUAD_CurrentVersionRun_bf29 {
  strings:
    $key_bf29 = { ec 46 [2] c8 48 [2] e3 64 [2] cd 46 [2] d9 5d [2] d6 47 [2] c8 5a [2] ca 5b [2] d1 5d [2] cd 5a [2] d1 75 }

  condition:
    any of them
}