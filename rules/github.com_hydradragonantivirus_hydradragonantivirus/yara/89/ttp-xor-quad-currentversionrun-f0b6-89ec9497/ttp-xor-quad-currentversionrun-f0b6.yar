rule TTP_XOR_QUAD_CurrentVersionRun_f0b6 {
  strings:
    $key_f0b6 = { a3 d9 [2] 87 d7 [2] ac fb [2] 82 d9 [2] 96 c2 [2] 99 d8 [2] 87 c5 [2] 85 c4 [2] 9e c2 [2] 82 c5 [2] 9e ea }

  condition:
    any of them
}