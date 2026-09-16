rule TTP_XOR_QUAD_CurrentVersionRun_3c80 {
  strings:
    $key_3c80 = { 6f ef [2] 4b e1 [2] 60 cd [2] 4e ef [2] 5a f4 [2] 55 ee [2] 4b f3 [2] 49 f2 [2] 52 f4 [2] 4e f3 [2] 52 dc }

  condition:
    any of them
}