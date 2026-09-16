rule TTP_XOR_QUAD_CurrentVersionRun_f0f7 {
  strings:
    $key_f0f7 = { a3 98 [2] 87 96 [2] ac ba [2] 82 98 [2] 96 83 [2] 99 99 [2] 87 84 [2] 85 85 [2] 9e 83 [2] 82 84 [2] 9e ab }

  condition:
    any of them
}