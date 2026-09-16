rule TTP_XOR_QUAD_CurrentVersionRun_0a80 {
  strings:
    $key_0a80 = { 59 ef [2] 7d e1 [2] 56 cd [2] 78 ef [2] 6c f4 [2] 63 ee [2] 7d f3 [2] 7f f2 [2] 64 f4 [2] 78 f3 [2] 64 dc }

  condition:
    any of them
}