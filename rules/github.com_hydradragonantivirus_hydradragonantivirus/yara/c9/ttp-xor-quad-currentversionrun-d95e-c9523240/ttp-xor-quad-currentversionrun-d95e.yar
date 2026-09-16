rule TTP_XOR_QUAD_CurrentVersionRun_d95e {
  strings:
    $key_d95e = { 8a 31 [2] ae 3f [2] 85 13 [2] ab 31 [2] bf 2a [2] b0 30 [2] ae 2d [2] ac 2c [2] b7 2a [2] ab 2d [2] b7 02 }

  condition:
    any of them
}