rule TTP_XOR_QUAD_CurrentVersionRun_d95a {
  strings:
    $key_d95a = { 8a 35 [2] ae 3b [2] 85 17 [2] ab 35 [2] bf 2e [2] b0 34 [2] ae 29 [2] ac 28 [2] b7 2e [2] ab 29 [2] b7 06 }

  condition:
    any of them
}