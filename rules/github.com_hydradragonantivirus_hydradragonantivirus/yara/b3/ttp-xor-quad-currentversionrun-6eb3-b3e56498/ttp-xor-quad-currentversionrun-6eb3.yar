rule TTP_XOR_QUAD_CurrentVersionRun_6eb3 {
  strings:
    $key_6eb3 = { 3d dc [2] 19 d2 [2] 32 fe [2] 1c dc [2] 08 c7 [2] 07 dd [2] 19 c0 [2] 1b c1 [2] 00 c7 [2] 1c c0 [2] 00 ef }

  condition:
    any of them
}