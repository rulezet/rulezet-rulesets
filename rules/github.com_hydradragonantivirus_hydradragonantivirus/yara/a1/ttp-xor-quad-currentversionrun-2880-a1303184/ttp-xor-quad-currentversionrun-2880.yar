rule TTP_XOR_QUAD_CurrentVersionRun_2880 {
  strings:
    $key_2880 = { 7b ef [2] 5f e1 [2] 74 cd [2] 5a ef [2] 4e f4 [2] 41 ee [2] 5f f3 [2] 5d f2 [2] 46 f4 [2] 5a f3 [2] 46 dc }

  condition:
    any of them
}