rule TTP_XOR_QUAD_CurrentVersionRun_20f7 {
  strings:
    $key_20f7 = { 73 98 [2] 57 96 [2] 7c ba [2] 52 98 [2] 46 83 [2] 49 99 [2] 57 84 [2] 55 85 [2] 4e 83 [2] 52 84 [2] 4e ab }

  condition:
    any of them
}