rule TTP_XOR_QUAD_CurrentVersionRun_61fa {
  strings:
    $key_61fa = { 32 95 [2] 16 9b [2] 3d b7 [2] 13 95 [2] 07 8e [2] 08 94 [2] 16 89 [2] 14 88 [2] 0f 8e [2] 13 89 [2] 0f a6 }

  condition:
    any of them
}