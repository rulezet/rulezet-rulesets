rule TTP_XOR_QUAD_CurrentVersionRun_bfb6 {
  strings:
    $key_bfb6 = { ec d9 [2] c8 d7 [2] e3 fb [2] cd d9 [2] d9 c2 [2] d6 d8 [2] c8 c5 [2] ca c4 [2] d1 c2 [2] cd c5 [2] d1 ea }

  condition:
    any of them
}