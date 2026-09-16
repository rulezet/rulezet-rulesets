rule TTP_XOR_QUAD_CurrentVersionRun_6180 {
  strings:
    $key_6180 = { 32 ef [2] 16 e1 [2] 3d cd [2] 13 ef [2] 07 f4 [2] 08 ee [2] 16 f3 [2] 14 f2 [2] 0f f4 [2] 13 f3 [2] 0f dc }

  condition:
    any of them
}