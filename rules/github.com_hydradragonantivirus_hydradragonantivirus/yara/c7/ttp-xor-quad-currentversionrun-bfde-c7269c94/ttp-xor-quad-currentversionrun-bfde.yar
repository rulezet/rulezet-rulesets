rule TTP_XOR_QUAD_CurrentVersionRun_bfde {
  strings:
    $key_bfde = { ec b1 [2] c8 bf [2] e3 93 [2] cd b1 [2] d9 aa [2] d6 b0 [2] c8 ad [2] ca ac [2] d1 aa [2] cd ad [2] d1 82 }

  condition:
    any of them
}