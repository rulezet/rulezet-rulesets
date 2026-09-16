rule TTP_XOR_QUAD_CurrentVersionRun_0d80 {
  strings:
    $key_0d80 = { 5e ef [2] 7a e1 [2] 51 cd [2] 7f ef [2] 6b f4 [2] 64 ee [2] 7a f3 [2] 78 f2 [2] 63 f4 [2] 7f f3 [2] 63 dc }

  condition:
    any of them
}