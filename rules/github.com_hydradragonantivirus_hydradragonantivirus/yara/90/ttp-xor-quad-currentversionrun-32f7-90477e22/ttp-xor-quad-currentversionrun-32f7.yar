rule TTP_XOR_QUAD_CurrentVersionRun_32f7 {
  strings:
    $key_32f7 = { 61 98 [2] 45 96 [2] 6e ba [2] 40 98 [2] 54 83 [2] 5b 99 [2] 45 84 [2] 47 85 [2] 5c 83 [2] 40 84 [2] 5c ab }

  condition:
    any of them
}