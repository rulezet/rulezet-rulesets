rule TTP_XOR_QUAD_CurrentVersionRun_e8f7 {
  strings:
    $key_e8f7 = { bb 98 [2] 9f 96 [2] b4 ba [2] 9a 98 [2] 8e 83 [2] 81 99 [2] 9f 84 [2] 9d 85 [2] 86 83 [2] 9a 84 [2] 86 ab }

  condition:
    any of them
}