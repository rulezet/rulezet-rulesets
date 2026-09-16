rule TTP_XOR_QUAD_CurrentVersionRun_6188 {
  strings:
    $key_6188 = { 32 e7 [2] 16 e9 [2] 3d c5 [2] 13 e7 [2] 07 fc [2] 08 e6 [2] 16 fb [2] 14 fa [2] 0f fc [2] 13 fb [2] 0f d4 }

  condition:
    any of them
}