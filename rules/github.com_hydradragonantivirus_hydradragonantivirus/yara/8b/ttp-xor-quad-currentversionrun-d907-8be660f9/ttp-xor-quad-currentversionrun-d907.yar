rule TTP_XOR_QUAD_CurrentVersionRun_d907 {
  strings:
    $key_d907 = { 8a 68 [2] ae 66 [2] 85 4a [2] ab 68 [2] bf 73 [2] b0 69 [2] ae 74 [2] ac 75 [2] b7 73 [2] ab 74 [2] b7 5b }

  condition:
    any of them
}