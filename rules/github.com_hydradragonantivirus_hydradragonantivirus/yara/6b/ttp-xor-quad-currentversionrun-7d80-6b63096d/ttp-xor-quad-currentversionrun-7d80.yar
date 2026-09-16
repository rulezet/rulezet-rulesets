rule TTP_XOR_QUAD_CurrentVersionRun_7d80 {
  strings:
    $key_7d80 = { 2e ef [2] 0a e1 [2] 21 cd [2] 0f ef [2] 1b f4 [2] 14 ee [2] 0a f3 [2] 08 f2 [2] 13 f4 [2] 0f f3 [2] 13 dc }

  condition:
    any of them
}