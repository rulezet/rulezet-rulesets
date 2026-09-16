rule TTP_XOR_QUAD_CurrentVersionRun_0980 {
  strings:
    $key_0980 = { 5a ef [2] 7e e1 [2] 55 cd [2] 7b ef [2] 6f f4 [2] 60 ee [2] 7e f3 [2] 7c f2 [2] 67 f4 [2] 7b f3 [2] 67 dc }

  condition:
    any of them
}