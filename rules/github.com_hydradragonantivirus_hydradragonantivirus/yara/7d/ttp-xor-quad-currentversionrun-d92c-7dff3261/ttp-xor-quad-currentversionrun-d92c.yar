rule TTP_XOR_QUAD_CurrentVersionRun_d92c {
  strings:
    $key_d92c = { 8a 43 [2] ae 4d [2] 85 61 [2] ab 43 [2] bf 58 [2] b0 42 [2] ae 5f [2] ac 5e [2] b7 58 [2] ab 5f [2] b7 70 }

  condition:
    any of them
}