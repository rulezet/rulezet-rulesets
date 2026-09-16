rule TTP_XOR_QUAD_CurrentVersionRun_ba2a {
  strings:
    $key_ba2a = { e9 45 [2] cd 4b [2] e6 67 [2] c8 45 [2] dc 5e [2] d3 44 [2] cd 59 [2] cf 58 [2] d4 5e [2] c8 59 [2] d4 76 }

  condition:
    any of them
}