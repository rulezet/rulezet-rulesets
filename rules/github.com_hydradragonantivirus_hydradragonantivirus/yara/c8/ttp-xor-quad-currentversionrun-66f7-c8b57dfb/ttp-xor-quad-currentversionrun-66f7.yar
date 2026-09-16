rule TTP_XOR_QUAD_CurrentVersionRun_66f7 {
  strings:
    $key_66f7 = { 35 98 [2] 11 96 [2] 3a ba [2] 14 98 [2] 00 83 [2] 0f 99 [2] 11 84 [2] 13 85 [2] 08 83 [2] 14 84 [2] 08 ab }

  condition:
    any of them
}