rule TTP_XOR_QUAD_CurrentVersionRun_d94e {
  strings:
    $key_d94e = { 8a 21 [2] ae 2f [2] 85 03 [2] ab 21 [2] bf 3a [2] b0 20 [2] ae 3d [2] ac 3c [2] b7 3a [2] ab 3d [2] b7 12 }

  condition:
    any of them
}