rule TTP_XOR_QUAD_CurrentVersionRun_d963 {
  strings:
    $key_d963 = { 8a 0c [2] ae 02 [2] 85 2e [2] ab 0c [2] bf 17 [2] b0 0d [2] ae 10 [2] ac 11 [2] b7 17 [2] ab 10 [2] b7 3f }

  condition:
    any of them
}