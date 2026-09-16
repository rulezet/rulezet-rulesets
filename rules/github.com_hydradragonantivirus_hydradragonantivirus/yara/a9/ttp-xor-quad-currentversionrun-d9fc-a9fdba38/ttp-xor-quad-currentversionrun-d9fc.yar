rule TTP_XOR_QUAD_CurrentVersionRun_d9fc {
  strings:
    $key_d9fc = { 8a 93 [2] ae 9d [2] 85 b1 [2] ab 93 [2] bf 88 [2] b0 92 [2] ae 8f [2] ac 8e [2] b7 88 [2] ab 8f [2] b7 a0 }

  condition:
    any of them
}