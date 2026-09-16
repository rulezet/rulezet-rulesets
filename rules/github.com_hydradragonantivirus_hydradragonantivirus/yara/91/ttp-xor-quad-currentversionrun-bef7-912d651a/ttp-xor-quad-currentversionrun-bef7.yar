rule TTP_XOR_QUAD_CurrentVersionRun_bef7 {
  strings:
    $key_bef7 = { ed 98 [2] c9 96 [2] e2 ba [2] cc 98 [2] d8 83 [2] d7 99 [2] c9 84 [2] cb 85 [2] d0 83 [2] cc 84 [2] d0 ab }

  condition:
    any of them
}