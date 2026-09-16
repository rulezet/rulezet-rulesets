rule TTP_XOR_QUAD_CurrentVersionRun_61e0 {
  strings:
    $key_61e0 = { 32 8f [2] 16 81 [2] 3d ad [2] 13 8f [2] 07 94 [2] 08 8e [2] 16 93 [2] 14 92 [2] 0f 94 [2] 13 93 [2] 0f bc }

  condition:
    any of them
}