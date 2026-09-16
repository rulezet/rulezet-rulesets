rule TTP_XOR_QUAD_CurrentVersionRun_61ca {
  strings:
    $key_61ca = { 32 a5 [2] 16 ab [2] 3d 87 [2] 13 a5 [2] 07 be [2] 08 a4 [2] 16 b9 [2] 14 b8 [2] 0f be [2] 13 b9 [2] 0f 96 }

  condition:
    any of them
}