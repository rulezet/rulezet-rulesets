rule TTP_XOR_QUAD_CurrentVersionRun_d9ea {
  strings:
    $key_d9ea = { 8a 85 [2] ae 8b [2] 85 a7 [2] ab 85 [2] bf 9e [2] b0 84 [2] ae 99 [2] ac 98 [2] b7 9e [2] ab 99 [2] b7 b6 }

  condition:
    any of them
}