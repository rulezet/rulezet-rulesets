rule TTP_XOR_QUAD_CurrentVersionRun_61aa {
  strings:
    $key_61aa = { 32 c5 [2] 16 cb [2] 3d e7 [2] 13 c5 [2] 07 de [2] 08 c4 [2] 16 d9 [2] 14 d8 [2] 0f de [2] 13 d9 [2] 0f f6 }

  condition:
    any of them
}