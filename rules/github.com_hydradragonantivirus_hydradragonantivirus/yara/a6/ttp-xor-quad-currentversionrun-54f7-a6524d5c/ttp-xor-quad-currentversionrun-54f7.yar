rule TTP_XOR_QUAD_CurrentVersionRun_54f7 {
  strings:
    $key_54f7 = { 07 98 [2] 23 96 [2] 08 ba [2] 26 98 [2] 32 83 [2] 3d 99 [2] 23 84 [2] 21 85 [2] 3a 83 [2] 26 84 [2] 3a ab }

  condition:
    any of them
}