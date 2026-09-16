rule TTP_XOR_QUAD_CurrentVersionRun_04f7 {
  strings:
    $key_04f7 = { 57 98 [2] 73 96 [2] 58 ba [2] 76 98 [2] 62 83 [2] 6d 99 [2] 73 84 [2] 71 85 [2] 6a 83 [2] 76 84 [2] 6a ab }

  condition:
    any of them
}