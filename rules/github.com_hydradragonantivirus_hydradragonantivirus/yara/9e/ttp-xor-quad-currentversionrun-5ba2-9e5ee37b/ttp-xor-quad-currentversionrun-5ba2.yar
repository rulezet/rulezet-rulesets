rule TTP_XOR_QUAD_CurrentVersionRun_5ba2 {
  strings:
    $key_5ba2 = { 08 cd [2] 2c c3 [2] 07 ef [2] 29 cd [2] 3d d6 [2] 32 cc [2] 2c d1 [2] 2e d0 [2] 35 d6 [2] 29 d1 [2] 35 fe }

  condition:
    any of them
}