rule TTP_XOR_QUAD_CurrentVersionRun_d974 {
  strings:
    $key_d974 = { 8a 1b [2] ae 15 [2] 85 39 [2] ab 1b [2] bf 00 [2] b0 1a [2] ae 07 [2] ac 06 [2] b7 00 [2] ab 07 [2] b7 28 }

  condition:
    any of them
}