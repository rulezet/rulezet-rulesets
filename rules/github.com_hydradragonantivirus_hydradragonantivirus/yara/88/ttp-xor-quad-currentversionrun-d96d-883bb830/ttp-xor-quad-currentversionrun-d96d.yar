rule TTP_XOR_QUAD_CurrentVersionRun_d96d {
  strings:
    $key_d96d = { 8a 02 [2] ae 0c [2] 85 20 [2] ab 02 [2] bf 19 [2] b0 03 [2] ae 1e [2] ac 1f [2] b7 19 [2] ab 1e [2] b7 31 }

  condition:
    any of them
}