rule TTP_XOR_QUAD_CurrentVersionRun_d96e {
  strings:
    $key_d96e = { 8a 01 [2] ae 0f [2] 85 23 [2] ab 01 [2] bf 1a [2] b0 00 [2] ae 1d [2] ac 1c [2] b7 1a [2] ab 1d [2] b7 32 }

  condition:
    any of them
}