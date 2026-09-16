rule TTP_XOR_QUAD_CurrentVersionRun_1627 {
  strings:
    $key_1627 = { 45 48 [2] 61 46 [2] 4a 6a [2] 64 48 [2] 70 53 [2] 7f 49 [2] 61 54 [2] 63 55 [2] 78 53 [2] 64 54 [2] 78 7b }

  condition:
    any of them
}