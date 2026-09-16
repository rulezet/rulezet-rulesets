rule TTP_XOR_QUAD_CurrentVersionRun_69f7 {
  strings:
    $key_69f7 = { 3a 98 [2] 1e 96 [2] 35 ba [2] 1b 98 [2] 0f 83 [2] 00 99 [2] 1e 84 [2] 1c 85 [2] 07 83 [2] 1b 84 [2] 07 ab }

  condition:
    any of them
}