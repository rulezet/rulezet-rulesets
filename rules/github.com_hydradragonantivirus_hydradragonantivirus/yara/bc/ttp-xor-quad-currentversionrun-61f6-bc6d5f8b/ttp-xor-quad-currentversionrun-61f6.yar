rule TTP_XOR_QUAD_CurrentVersionRun_61f6 {
  strings:
    $key_61f6 = { 32 99 [2] 16 97 [2] 3d bb [2] 13 99 [2] 07 82 [2] 08 98 [2] 16 85 [2] 14 84 [2] 0f 82 [2] 13 85 [2] 0f aa }

  condition:
    any of them
}