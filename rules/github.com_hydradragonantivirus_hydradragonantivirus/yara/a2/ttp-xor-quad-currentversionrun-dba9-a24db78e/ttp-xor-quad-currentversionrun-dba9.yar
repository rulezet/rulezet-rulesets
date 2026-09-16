rule TTP_XOR_QUAD_CurrentVersionRun_dba9 {
  strings:
    $key_dba9 = { 88 c6 [2] ac c8 [2] 87 e4 [2] a9 c6 [2] bd dd [2] b2 c7 [2] ac da [2] ae db [2] b5 dd [2] a9 da [2] b5 f5 }

  condition:
    any of them
}