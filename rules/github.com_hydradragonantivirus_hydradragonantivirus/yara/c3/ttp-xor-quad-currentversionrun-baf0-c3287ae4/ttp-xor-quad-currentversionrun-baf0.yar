rule TTP_XOR_QUAD_CurrentVersionRun_baf0 {
  strings:
    $key_baf0 = { e9 9f [2] cd 91 [2] e6 bd [2] c8 9f [2] dc 84 [2] d3 9e [2] cd 83 [2] cf 82 [2] d4 84 [2] c8 83 [2] d4 ac }

  condition:
    any of them
}