rule TTP_XOR_QUAD_CurrentVersionRun_fc80 {
  strings:
    $key_fc80 = { af ef [2] 8b e1 [2] a0 cd [2] 8e ef [2] 9a f4 [2] 95 ee [2] 8b f3 [2] 89 f2 [2] 92 f4 [2] 8e f3 [2] 92 dc }

  condition:
    any of them
}