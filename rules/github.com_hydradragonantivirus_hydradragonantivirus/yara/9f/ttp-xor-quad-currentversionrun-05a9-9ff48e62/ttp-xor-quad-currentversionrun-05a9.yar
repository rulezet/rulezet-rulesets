rule TTP_XOR_QUAD_CurrentVersionRun_05a9 {
  strings:
    $key_05a9 = { 56 c6 [2] 72 c8 [2] 59 e4 [2] 77 c6 [2] 63 dd [2] 6c c7 [2] 72 da [2] 70 db [2] 6b dd [2] 77 da [2] 6b f5 }

  condition:
    any of them
}