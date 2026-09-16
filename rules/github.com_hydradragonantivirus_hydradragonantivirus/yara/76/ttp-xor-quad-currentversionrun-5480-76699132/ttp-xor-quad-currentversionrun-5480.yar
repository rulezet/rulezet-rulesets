rule TTP_XOR_QUAD_CurrentVersionRun_5480 {
  strings:
    $key_5480 = { 07 ef [2] 23 e1 [2] 08 cd [2] 26 ef [2] 32 f4 [2] 3d ee [2] 23 f3 [2] 21 f2 [2] 3a f4 [2] 26 f3 [2] 3a dc }

  condition:
    any of them
}