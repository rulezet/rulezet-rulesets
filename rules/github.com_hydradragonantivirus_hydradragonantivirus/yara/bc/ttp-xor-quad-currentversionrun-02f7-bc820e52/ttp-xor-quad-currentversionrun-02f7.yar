rule TTP_XOR_QUAD_CurrentVersionRun_02f7 {
  strings:
    $key_02f7 = { 51 98 [2] 75 96 [2] 5e ba [2] 70 98 [2] 64 83 [2] 6b 99 [2] 75 84 [2] 77 85 [2] 6c 83 [2] 70 84 [2] 6c ab }

  condition:
    any of them
}