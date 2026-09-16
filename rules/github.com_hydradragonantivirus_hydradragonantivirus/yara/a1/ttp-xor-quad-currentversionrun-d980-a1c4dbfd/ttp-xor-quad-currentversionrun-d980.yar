rule TTP_XOR_QUAD_CurrentVersionRun_d980 {
  strings:
    $key_d980 = { 8a ef [2] ae e1 [2] 85 cd [2] ab ef [2] bf f4 [2] b0 ee [2] ae f3 [2] ac f2 [2] b7 f4 [2] ab f3 [2] b7 dc }

  condition:
    any of them
}