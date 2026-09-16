rule TTP_XOR_QUAD_CurrentVersionRun_0880 {
  strings:
    $key_0880 = { 5b ef [2] 7f e1 [2] 54 cd [2] 7a ef [2] 6e f4 [2] 61 ee [2] 7f f3 [2] 7d f2 [2] 66 f4 [2] 7a f3 [2] 66 dc }

  condition:
    any of them
}