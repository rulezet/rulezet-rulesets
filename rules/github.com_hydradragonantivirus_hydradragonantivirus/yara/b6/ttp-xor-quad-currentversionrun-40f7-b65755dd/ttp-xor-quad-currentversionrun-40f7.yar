rule TTP_XOR_QUAD_CurrentVersionRun_40f7 {
  strings:
    $key_40f7 = { 13 98 [2] 37 96 [2] 1c ba [2] 32 98 [2] 26 83 [2] 29 99 [2] 37 84 [2] 35 85 [2] 2e 83 [2] 32 84 [2] 2e ab }

  condition:
    any of them
}