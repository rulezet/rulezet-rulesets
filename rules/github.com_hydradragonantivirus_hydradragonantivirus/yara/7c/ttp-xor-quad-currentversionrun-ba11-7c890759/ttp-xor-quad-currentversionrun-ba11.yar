rule TTP_XOR_QUAD_CurrentVersionRun_ba11 {
  strings:
    $key_ba11 = { e9 7e [2] cd 70 [2] e6 5c [2] c8 7e [2] dc 65 [2] d3 7f [2] cd 62 [2] cf 63 [2] d4 65 [2] c8 62 [2] d4 4d }

  condition:
    any of them
}