rule TTP_XOR_QUAD_CurrentVersionRun_c480 {
  strings:
    $key_c480 = { 97 ef [2] b3 e1 [2] 98 cd [2] b6 ef [2] a2 f4 [2] ad ee [2] b3 f3 [2] b1 f2 [2] aa f4 [2] b6 f3 [2] aa dc }

  condition:
    any of them
}