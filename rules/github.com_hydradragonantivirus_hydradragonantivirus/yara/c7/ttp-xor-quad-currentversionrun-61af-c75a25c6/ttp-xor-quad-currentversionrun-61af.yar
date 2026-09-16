rule TTP_XOR_QUAD_CurrentVersionRun_61af {
  strings:
    $key_61af = { 32 c0 [2] 16 ce [2] 3d e2 [2] 13 c0 [2] 07 db [2] 08 c1 [2] 16 dc [2] 14 dd [2] 0f db [2] 13 dc [2] 0f f3 }

  condition:
    any of them
}