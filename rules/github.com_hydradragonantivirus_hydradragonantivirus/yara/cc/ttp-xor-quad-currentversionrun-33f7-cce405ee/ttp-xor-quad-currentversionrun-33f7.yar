rule TTP_XOR_QUAD_CurrentVersionRun_33f7 {
  strings:
    $key_33f7 = { 60 98 [2] 44 96 [2] 6f ba [2] 41 98 [2] 55 83 [2] 5a 99 [2] 44 84 [2] 46 85 [2] 5d 83 [2] 41 84 [2] 5d ab }

  condition:
    any of them
}