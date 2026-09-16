rule TTP_XOR_QUAD_CurrentVersionRun_d900 {
  strings:
    $key_d900 = { 8a 6f [2] ae 61 [2] 85 4d [2] ab 6f [2] bf 74 [2] b0 6e [2] ae 73 [2] ac 72 [2] b7 74 [2] ab 73 [2] b7 5c }

  condition:
    any of them
}