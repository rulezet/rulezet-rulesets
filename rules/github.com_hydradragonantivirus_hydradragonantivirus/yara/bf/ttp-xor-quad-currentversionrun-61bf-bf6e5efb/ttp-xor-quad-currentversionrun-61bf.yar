rule TTP_XOR_QUAD_CurrentVersionRun_61bf {
  strings:
    $key_61bf = { 32 d0 [2] 16 de [2] 3d f2 [2] 13 d0 [2] 07 cb [2] 08 d1 [2] 16 cc [2] 14 cd [2] 0f cb [2] 13 cc [2] 0f e3 }

  condition:
    any of them
}