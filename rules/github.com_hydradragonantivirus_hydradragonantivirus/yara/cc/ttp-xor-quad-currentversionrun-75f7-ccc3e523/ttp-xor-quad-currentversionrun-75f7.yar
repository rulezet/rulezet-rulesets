rule TTP_XOR_QUAD_CurrentVersionRun_75f7 {
  strings:
    $key_75f7 = { 26 98 [2] 02 96 [2] 29 ba [2] 07 98 [2] 13 83 [2] 1c 99 [2] 02 84 [2] 00 85 [2] 1b 83 [2] 07 84 [2] 1b ab }

  condition:
    any of them
}