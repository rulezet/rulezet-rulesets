rule TTP_XOR_QUAD_CurrentVersionRun_bf68 {
  strings:
    $key_bf68 = { ec 07 [2] c8 09 [2] e3 25 [2] cd 07 [2] d9 1c [2] d6 06 [2] c8 1b [2] ca 1a [2] d1 1c [2] cd 1b [2] d1 34 }

  condition:
    any of them
}