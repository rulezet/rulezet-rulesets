rule TTP_XOR_QUAD_CurrentVersionRun_bae1 {
  strings:
    $key_bae1 = { e9 8e [2] cd 80 [2] e6 ac [2] c8 8e [2] dc 95 [2] d3 8f [2] cd 92 [2] cf 93 [2] d4 95 [2] c8 92 [2] d4 bd }

  condition:
    any of them
}