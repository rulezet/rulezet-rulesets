rule TTP_XOR_QUAD_CurrentVersionRun_bf77 {
  strings:
    $key_bf77 = { ec 18 [2] c8 16 [2] e3 3a [2] cd 18 [2] d9 03 [2] d6 19 [2] c8 04 [2] ca 05 [2] d1 03 [2] cd 04 [2] d1 2b }

  condition:
    any of them
}