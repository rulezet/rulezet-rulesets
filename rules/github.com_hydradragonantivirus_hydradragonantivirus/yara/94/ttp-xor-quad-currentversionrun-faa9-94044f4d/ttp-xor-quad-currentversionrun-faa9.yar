rule TTP_XOR_QUAD_CurrentVersionRun_faa9 {
  strings:
    $key_faa9 = { a9 c6 [2] 8d c8 [2] a6 e4 [2] 88 c6 [2] 9c dd [2] 93 c7 [2] 8d da [2] 8f db [2] 94 dd [2] 88 da [2] 94 f5 }

  condition:
    any of them
}