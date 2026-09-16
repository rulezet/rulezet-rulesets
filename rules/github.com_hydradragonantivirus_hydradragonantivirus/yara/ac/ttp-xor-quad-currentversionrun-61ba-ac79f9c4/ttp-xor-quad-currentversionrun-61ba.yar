rule TTP_XOR_QUAD_CurrentVersionRun_61ba {
  strings:
    $key_61ba = { 32 d5 [2] 16 db [2] 3d f7 [2] 13 d5 [2] 07 ce [2] 08 d4 [2] 16 c9 [2] 14 c8 [2] 0f ce [2] 13 c9 [2] 0f e6 }

  condition:
    any of them
}