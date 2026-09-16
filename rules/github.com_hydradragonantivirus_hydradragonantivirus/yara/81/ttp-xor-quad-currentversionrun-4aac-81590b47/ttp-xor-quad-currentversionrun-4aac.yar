rule TTP_XOR_QUAD_CurrentVersionRun_4aac {
  strings:
    $key_4aac = { 19 c3 [2] 3d cd [2] 16 e1 [2] 38 c3 [2] 2c d8 [2] 23 c2 [2] 3d df [2] 3f de [2] 24 d8 [2] 38 df [2] 24 f0 }

  condition:
    any of them
}