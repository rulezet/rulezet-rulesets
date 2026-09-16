rule TTP_XOR_QUAD_CurrentVersionRun_28f7 {
  strings:
    $key_28f7 = { 7b 98 [2] 5f 96 [2] 74 ba [2] 5a 98 [2] 4e 83 [2] 41 99 [2] 5f 84 [2] 5d 85 [2] 46 83 [2] 5a 84 [2] 46 ab }

  condition:
    any of them
}