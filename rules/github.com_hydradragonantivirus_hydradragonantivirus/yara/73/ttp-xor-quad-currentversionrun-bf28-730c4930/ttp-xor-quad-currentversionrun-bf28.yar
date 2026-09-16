rule TTP_XOR_QUAD_CurrentVersionRun_bf28 {
  strings:
    $key_bf28 = { ec 47 [2] c8 49 [2] e3 65 [2] cd 47 [2] d9 5c [2] d6 46 [2] c8 5b [2] ca 5a [2] d1 5c [2] cd 5b [2] d1 74 }

  condition:
    any of them
}