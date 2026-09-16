rule TTP_XOR_QUAD_CurrentVersionRun_55f7 {
  strings:
    $key_55f7 = { 06 98 [2] 22 96 [2] 09 ba [2] 27 98 [2] 33 83 [2] 3c 99 [2] 22 84 [2] 20 85 [2] 3b 83 [2] 27 84 [2] 3b ab }

  condition:
    any of them
}