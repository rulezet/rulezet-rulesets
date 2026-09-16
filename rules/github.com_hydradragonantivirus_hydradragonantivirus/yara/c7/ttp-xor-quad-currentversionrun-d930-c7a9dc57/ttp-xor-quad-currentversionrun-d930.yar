rule TTP_XOR_QUAD_CurrentVersionRun_d930 {
  strings:
    $key_d930 = { 8a 5f [2] ae 51 [2] 85 7d [2] ab 5f [2] bf 44 [2] b0 5e [2] ae 43 [2] ac 42 [2] b7 44 [2] ab 43 [2] b7 6c }

  condition:
    any of them
}