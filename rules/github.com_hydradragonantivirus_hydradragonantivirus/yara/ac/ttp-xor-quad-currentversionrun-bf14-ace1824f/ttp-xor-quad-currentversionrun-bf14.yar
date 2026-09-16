rule TTP_XOR_QUAD_CurrentVersionRun_bf14 {
  strings:
    $key_bf14 = { ec 7b [2] c8 75 [2] e3 59 [2] cd 7b [2] d9 60 [2] d6 7a [2] c8 67 [2] ca 66 [2] d1 60 [2] cd 67 [2] d1 48 }

  condition:
    any of them
}