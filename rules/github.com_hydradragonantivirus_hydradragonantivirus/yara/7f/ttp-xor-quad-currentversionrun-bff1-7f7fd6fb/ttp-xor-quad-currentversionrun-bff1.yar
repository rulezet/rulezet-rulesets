rule TTP_XOR_QUAD_CurrentVersionRun_bff1 {
  strings:
    $key_bff1 = { ec 9e [2] c8 90 [2] e3 bc [2] cd 9e [2] d9 85 [2] d6 9f [2] c8 82 [2] ca 83 [2] d1 85 [2] cd 82 [2] d1 ad }

  condition:
    any of them
}