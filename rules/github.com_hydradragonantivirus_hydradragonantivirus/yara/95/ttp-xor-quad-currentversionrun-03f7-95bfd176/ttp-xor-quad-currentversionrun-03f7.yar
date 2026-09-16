rule TTP_XOR_QUAD_CurrentVersionRun_03f7 {
  strings:
    $key_03f7 = { 50 98 [2] 74 96 [2] 5f ba [2] 71 98 [2] 65 83 [2] 6a 99 [2] 74 84 [2] 76 85 [2] 6d 83 [2] 71 84 [2] 6d ab }

  condition:
    any of them
}