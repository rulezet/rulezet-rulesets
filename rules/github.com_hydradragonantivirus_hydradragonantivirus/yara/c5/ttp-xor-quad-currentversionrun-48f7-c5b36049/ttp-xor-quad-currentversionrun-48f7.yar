rule TTP_XOR_QUAD_CurrentVersionRun_48f7 {
  strings:
    $key_48f7 = { 1b 98 [2] 3f 96 [2] 14 ba [2] 3a 98 [2] 2e 83 [2] 21 99 [2] 3f 84 [2] 3d 85 [2] 26 83 [2] 3a 84 [2] 26 ab }

  condition:
    any of them
}