rule TTP_XOR_QUAD_CurrentVersionRun_d950 {
  strings:
    $key_d950 = { 8a 3f [2] ae 31 [2] 85 1d [2] ab 3f [2] bf 24 [2] b0 3e [2] ae 23 [2] ac 22 [2] b7 24 [2] ab 23 [2] b7 0c }

  condition:
    any of them
}