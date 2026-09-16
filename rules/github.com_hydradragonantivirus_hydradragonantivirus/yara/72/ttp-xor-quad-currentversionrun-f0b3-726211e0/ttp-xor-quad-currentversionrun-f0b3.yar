rule TTP_XOR_QUAD_CurrentVersionRun_f0b3 {
  strings:
    $key_f0b3 = { a3 dc [2] 87 d2 [2] ac fe [2] 82 dc [2] 96 c7 [2] 99 dd [2] 87 c0 [2] 85 c1 [2] 9e c7 [2] 82 c0 [2] 9e ef }

  condition:
    any of them
}