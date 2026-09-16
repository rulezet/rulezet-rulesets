rule TTP_XOR_QUAD_CurrentVersionRun_d9f7 {
  strings:
    $key_d9f7 = { 8a 98 [2] ae 96 [2] 85 ba [2] ab 98 [2] bf 83 [2] b0 99 [2] ae 84 [2] ac 85 [2] b7 83 [2] ab 84 [2] b7 ab }

  condition:
    any of them
}