rule TTP_XOR_QUAD_CurrentVersionRun_bf04 {
  strings:
    $key_bf04 = { ec 6b [2] c8 65 [2] e3 49 [2] cd 6b [2] d9 70 [2] d6 6a [2] c8 77 [2] ca 76 [2] d1 70 [2] cd 77 [2] d1 58 }

  condition:
    any of them
}