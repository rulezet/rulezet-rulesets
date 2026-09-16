rule TTP_XOR_QUAD_CurrentVersionRun_bf11 {
  strings:
    $key_bf11 = { ec 7e [2] c8 70 [2] e3 5c [2] cd 7e [2] d9 65 [2] d6 7f [2] c8 62 [2] ca 63 [2] d1 65 [2] cd 62 [2] d1 4d }

  condition:
    any of them
}