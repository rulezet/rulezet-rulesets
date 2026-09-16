rule TTP_XOR_QUAD_CurrentVersionRun_dc80 {
  strings:
    $key_dc80 = { 8f ef [2] ab e1 [2] 80 cd [2] ae ef [2] ba f4 [2] b5 ee [2] ab f3 [2] a9 f2 [2] b2 f4 [2] ae f3 [2] b2 dc }

  condition:
    any of them
}