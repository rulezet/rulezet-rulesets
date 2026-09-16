rule TTP_XOR_QUAD_CurrentVersionRun_d933 {
  strings:
    $key_d933 = { 8a 5c [2] ae 52 [2] 85 7e [2] ab 5c [2] bf 47 [2] b0 5d [2] ae 40 [2] ac 41 [2] b7 47 [2] ab 40 [2] b7 6f }

  condition:
    any of them
}