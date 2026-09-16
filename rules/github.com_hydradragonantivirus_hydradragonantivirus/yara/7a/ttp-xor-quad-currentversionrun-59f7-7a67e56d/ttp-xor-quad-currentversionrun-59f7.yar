rule TTP_XOR_QUAD_CurrentVersionRun_59f7 {
  strings:
    $key_59f7 = { 0a 98 [2] 2e 96 [2] 05 ba [2] 2b 98 [2] 3f 83 [2] 30 99 [2] 2e 84 [2] 2c 85 [2] 37 83 [2] 2b 84 [2] 37 ab }

  condition:
    any of them
}