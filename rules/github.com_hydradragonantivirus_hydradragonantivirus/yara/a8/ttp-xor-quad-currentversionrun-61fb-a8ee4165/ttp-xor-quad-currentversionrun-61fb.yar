rule TTP_XOR_QUAD_CurrentVersionRun_61fb {
  strings:
    $key_61fb = { 32 94 [2] 16 9a [2] 3d b6 [2] 13 94 [2] 07 8f [2] 08 95 [2] 16 88 [2] 14 89 [2] 0f 8f [2] 13 88 [2] 0f a7 }

  condition:
    any of them
}