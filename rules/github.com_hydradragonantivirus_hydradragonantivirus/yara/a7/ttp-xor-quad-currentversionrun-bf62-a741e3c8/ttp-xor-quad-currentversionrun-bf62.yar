rule TTP_XOR_QUAD_CurrentVersionRun_bf62 {
  strings:
    $key_bf62 = { ec 0d [2] c8 03 [2] e3 2f [2] cd 0d [2] d9 16 [2] d6 0c [2] c8 11 [2] ca 10 [2] d1 16 [2] cd 11 [2] d1 3e }

  condition:
    any of them
}