rule TTP_XOR_QUAD_CurrentVersionRun_d92a {
  strings:
    $key_d92a = { 8a 45 [2] ae 4b [2] 85 67 [2] ab 45 [2] bf 5e [2] b0 44 [2] ae 59 [2] ac 58 [2] b7 5e [2] ab 59 [2] b7 76 }

  condition:
    any of them
}