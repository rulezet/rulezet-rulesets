rule TTP_XOR_QUAD_CurrentVersionRun_6eb5 {
  strings:
    $key_6eb5 = { 3d da [2] 19 d4 [2] 32 f8 [2] 1c da [2] 08 c1 [2] 07 db [2] 19 c6 [2] 1b c7 [2] 00 c1 [2] 1c c6 [2] 00 e9 }

  condition:
    any of them
}