rule TTP_XOR_QUAD_CurrentVersionRun_d96c {
  strings:
    $key_d96c = { 8a 03 [2] ae 0d [2] 85 21 [2] ab 03 [2] bf 18 [2] b0 02 [2] ae 1f [2] ac 1e [2] b7 18 [2] ab 1f [2] b7 30 }

  condition:
    any of them
}