rule TTP_XOR_QUAD_CurrentVersionRun_d880 {
  strings:
    $key_d880 = { 8b ef [2] af e1 [2] 84 cd [2] aa ef [2] be f4 [2] b1 ee [2] af f3 [2] ad f2 [2] b6 f4 [2] aa f3 [2] b6 dc }

  condition:
    any of them
}