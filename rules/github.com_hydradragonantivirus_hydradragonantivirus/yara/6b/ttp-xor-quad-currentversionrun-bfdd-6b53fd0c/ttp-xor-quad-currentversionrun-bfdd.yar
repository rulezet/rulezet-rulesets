rule TTP_XOR_QUAD_CurrentVersionRun_bfdd {
  strings:
    $key_bfdd = { ec b2 [2] c8 bc [2] e3 90 [2] cd b2 [2] d9 a9 [2] d6 b3 [2] c8 ae [2] ca af [2] d1 a9 [2] cd ae [2] d1 81 }

  condition:
    any of them
}