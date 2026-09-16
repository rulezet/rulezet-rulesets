rule TTP_XOR_QUAD_CurrentVersionRun_6c80 {
  strings:
    $key_6c80 = { 3f ef [2] 1b e1 [2] 30 cd [2] 1e ef [2] 0a f4 [2] 05 ee [2] 1b f3 [2] 19 f2 [2] 02 f4 [2] 1e f3 [2] 02 dc }

  condition:
    any of them
}