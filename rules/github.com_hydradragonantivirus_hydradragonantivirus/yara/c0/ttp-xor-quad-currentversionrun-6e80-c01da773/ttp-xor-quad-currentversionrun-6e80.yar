rule TTP_XOR_QUAD_CurrentVersionRun_6e80 {
  strings:
    $key_6e80 = { 3d ef [2] 19 e1 [2] 32 cd [2] 1c ef [2] 08 f4 [2] 07 ee [2] 19 f3 [2] 1b f2 [2] 00 f4 [2] 1c f3 [2] 00 dc }

  condition:
    any of them
}