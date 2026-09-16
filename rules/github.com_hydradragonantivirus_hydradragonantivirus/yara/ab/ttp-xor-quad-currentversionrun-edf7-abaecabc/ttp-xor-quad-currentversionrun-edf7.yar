rule TTP_XOR_QUAD_CurrentVersionRun_edf7 {
  strings:
    $key_edf7 = { be 98 [2] 9a 96 [2] b1 ba [2] 9f 98 [2] 8b 83 [2] 84 99 [2] 9a 84 [2] 98 85 [2] 83 83 [2] 9f 84 [2] 83 ab }

  condition:
    any of them
}