rule TTP_XOR_QUAD_CurrentVersionRun_d975 {
  strings:
    $key_d975 = { 8a 1a [2] ae 14 [2] 85 38 [2] ab 1a [2] bf 01 [2] b0 1b [2] ae 06 [2] ac 07 [2] b7 01 [2] ab 06 [2] b7 29 }

  condition:
    any of them
}