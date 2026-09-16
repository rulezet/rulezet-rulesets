rule TTP_XOR_QUAD_CurrentVersionRun_58f7 {
  strings:
    $key_58f7 = { 0b 98 [2] 2f 96 [2] 04 ba [2] 2a 98 [2] 3e 83 [2] 31 99 [2] 2f 84 [2] 2d 85 [2] 36 83 [2] 2a 84 [2] 36 ab }

  condition:
    any of them
}