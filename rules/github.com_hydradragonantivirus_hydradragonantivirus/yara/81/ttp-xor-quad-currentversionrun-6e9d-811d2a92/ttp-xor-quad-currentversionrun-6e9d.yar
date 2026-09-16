rule TTP_XOR_QUAD_CurrentVersionRun_6e9d {
  strings:
    $key_6e9d = { 3d f2 [2] 19 fc [2] 32 d0 [2] 1c f2 [2] 08 e9 [2] 07 f3 [2] 19 ee [2] 1b ef [2] 00 e9 [2] 1c ee [2] 00 c1 }

  condition:
    any of them
}