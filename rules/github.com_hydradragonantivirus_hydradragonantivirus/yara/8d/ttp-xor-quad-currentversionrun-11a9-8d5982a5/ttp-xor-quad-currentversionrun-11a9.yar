rule TTP_XOR_QUAD_CurrentVersionRun_11a9 {
  strings:
    $key_11a9 = { 42 c6 [2] 66 c8 [2] 4d e4 [2] 63 c6 [2] 77 dd [2] 78 c7 [2] 66 da [2] 64 db [2] 7f dd [2] 63 da [2] 7f f5 }

  condition:
    any of them
}