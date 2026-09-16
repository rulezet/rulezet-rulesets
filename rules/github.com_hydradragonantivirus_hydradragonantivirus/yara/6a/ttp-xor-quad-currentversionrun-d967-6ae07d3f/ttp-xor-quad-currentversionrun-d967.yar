rule TTP_XOR_QUAD_CurrentVersionRun_d967 {
  strings:
    $key_d967 = { 8a 08 [2] ae 06 [2] 85 2a [2] ab 08 [2] bf 13 [2] b0 09 [2] ae 14 [2] ac 15 [2] b7 13 [2] ab 14 [2] b7 3b }

  condition:
    any of them
}