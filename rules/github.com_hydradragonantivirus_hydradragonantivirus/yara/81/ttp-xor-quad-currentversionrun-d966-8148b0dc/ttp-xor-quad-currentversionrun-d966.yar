rule TTP_XOR_QUAD_CurrentVersionRun_d966 {
  strings:
    $key_d966 = { 8a 09 [2] ae 07 [2] 85 2b [2] ab 09 [2] bf 12 [2] b0 08 [2] ae 15 [2] ac 14 [2] b7 12 [2] ab 15 [2] b7 3a }

  condition:
    any of them
}