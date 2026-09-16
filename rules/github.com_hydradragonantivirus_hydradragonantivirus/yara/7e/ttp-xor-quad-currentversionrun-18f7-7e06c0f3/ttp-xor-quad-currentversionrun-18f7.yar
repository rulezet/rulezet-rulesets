rule TTP_XOR_QUAD_CurrentVersionRun_18f7 {
  strings:
    $key_18f7 = { 4b 98 [2] 6f 96 [2] 44 ba [2] 6a 98 [2] 7e 83 [2] 71 99 [2] 6f 84 [2] 6d 85 [2] 76 83 [2] 6a 84 [2] 76 ab }

  condition:
    any of them
}