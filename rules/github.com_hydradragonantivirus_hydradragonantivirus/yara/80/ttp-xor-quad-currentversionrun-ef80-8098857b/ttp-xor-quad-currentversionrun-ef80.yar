rule TTP_XOR_QUAD_CurrentVersionRun_ef80 {
  strings:
    $key_ef80 = { bc ef [2] 98 e1 [2] b3 cd [2] 9d ef [2] 89 f4 [2] 86 ee [2] 98 f3 [2] 9a f2 [2] 81 f4 [2] 9d f3 [2] 81 dc }

  condition:
    any of them
}