rule TTP_XOR_QUAD_CurrentVersionRun_d9ec {
  strings:
    $key_d9ec = { 8a 83 [2] ae 8d [2] 85 a1 [2] ab 83 [2] bf 98 [2] b0 82 [2] ae 9f [2] ac 9e [2] b7 98 [2] ab 9f [2] b7 b0 }

  condition:
    any of them
}