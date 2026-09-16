rule TTP_XOR_QUAD_CurrentVersionRun_d936 {
  strings:
    $key_d936 = { 8a 59 [2] ae 57 [2] 85 7b [2] ab 59 [2] bf 42 [2] b0 58 [2] ae 45 [2] ac 44 [2] b7 42 [2] ab 45 [2] b7 6a }

  condition:
    any of them
}