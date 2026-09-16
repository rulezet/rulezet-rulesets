rule TTP_XOR_QUAD_CurrentVersionRun_dd80 {
  strings:
    $key_dd80 = { 8e ef [2] aa e1 [2] 81 cd [2] af ef [2] bb f4 [2] b4 ee [2] aa f3 [2] a8 f2 [2] b3 f4 [2] af f3 [2] b3 dc }

  condition:
    any of them
}