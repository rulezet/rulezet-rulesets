rule TTP_XOR_QUAD_CurrentVersionRun_61f7 {
  strings:
    $key_61f7 = { 32 98 [2] 16 96 [2] 3d ba [2] 13 98 [2] 07 83 [2] 08 99 [2] 16 84 [2] 14 85 [2] 0f 83 [2] 13 84 [2] 0f ab }

  condition:
    any of them
}