rule TTP_XOR_QUAD_CurrentVersionRun_d96a {
  strings:
    $key_d96a = { 8a 05 [2] ae 0b [2] 85 27 [2] ab 05 [2] bf 1e [2] b0 04 [2] ae 19 [2] ac 18 [2] b7 1e [2] ab 19 [2] b7 36 }

  condition:
    any of them
}