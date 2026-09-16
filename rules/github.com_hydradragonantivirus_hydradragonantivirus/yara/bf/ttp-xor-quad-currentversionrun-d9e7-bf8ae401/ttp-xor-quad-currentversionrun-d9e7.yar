rule TTP_XOR_QUAD_CurrentVersionRun_d9e7 {
  strings:
    $key_d9e7 = { 8a 88 [2] ae 86 [2] 85 aa [2] ab 88 [2] bf 93 [2] b0 89 [2] ae 94 [2] ac 95 [2] b7 93 [2] ab 94 [2] b7 bb }

  condition:
    any of them
}