rule TTP_XOR_QUAD_CurrentVersionRun_efa9 {
  strings:
    $key_efa9 = { bc c6 [2] 98 c8 [2] b3 e4 [2] 9d c6 [2] 89 dd [2] 86 c7 [2] 98 da [2] 9a db [2] 81 dd [2] 9d da [2] 81 f5 }

  condition:
    any of them
}