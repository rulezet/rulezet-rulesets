rule TTP_XOR_QUAD_CurrentVersionRun_fcf7 {
  strings:
    $key_fcf7 = { af 98 [2] 8b 96 [2] a0 ba [2] 8e 98 [2] 9a 83 [2] 95 99 [2] 8b 84 [2] 89 85 [2] 92 83 [2] 8e 84 [2] 92 ab }

  condition:
    any of them
}