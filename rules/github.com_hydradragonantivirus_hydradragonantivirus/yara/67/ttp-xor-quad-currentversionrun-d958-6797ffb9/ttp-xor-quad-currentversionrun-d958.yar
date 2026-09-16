rule TTP_XOR_QUAD_CurrentVersionRun_d958 {
  strings:
    $key_d958 = { 8a 37 [2] ae 39 [2] 85 15 [2] ab 37 [2] bf 2c [2] b0 36 [2] ae 2b [2] ac 2a [2] b7 2c [2] ab 2b [2] b7 04 }

  condition:
    any of them
}