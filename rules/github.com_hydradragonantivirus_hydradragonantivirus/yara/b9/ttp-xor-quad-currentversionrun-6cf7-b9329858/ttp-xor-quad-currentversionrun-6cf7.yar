rule TTP_XOR_QUAD_CurrentVersionRun_6cf7 {
  strings:
    $key_6cf7 = { 3f 98 [2] 1b 96 [2] 30 ba [2] 1e 98 [2] 0a 83 [2] 05 99 [2] 1b 84 [2] 19 85 [2] 02 83 [2] 1e 84 [2] 02 ab }

  condition:
    any of them
}