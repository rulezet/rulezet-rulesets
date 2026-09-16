rule TTP_XOR_QUAD_CurrentVersionRun_bfe0 {
  strings:
    $key_bfe0 = { ec 8f [2] c8 81 [2] e3 ad [2] cd 8f [2] d9 94 [2] d6 8e [2] c8 93 [2] ca 92 [2] d1 94 [2] cd 93 [2] d1 bc }

  condition:
    any of them
}