rule TTP_XOR_QUAD_CurrentVersionRun_d961 {
  strings:
    $key_d961 = { 8a 0e [2] ae 00 [2] 85 2c [2] ab 0e [2] bf 15 [2] b0 0f [2] ae 12 [2] ac 13 [2] b7 15 [2] ab 12 [2] b7 3d }

  condition:
    any of them
}