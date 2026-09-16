rule TTP_XOR_QUAD_CurrentVersionRun_d923 {
  strings:
    $key_d923 = { 8a 4c [2] ae 42 [2] 85 6e [2] ab 4c [2] bf 57 [2] b0 4d [2] ae 50 [2] ac 51 [2] b7 57 [2] ab 50 [2] b7 7f }

  condition:
    any of them
}