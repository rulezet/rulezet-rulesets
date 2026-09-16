rule TTP_XOR_QUAD_CurrentVersionRun_e99b {
  strings:
    $key_e99b = { ba f4 [2] 9e fa [2] b5 d6 [2] 9b f4 [2] 8f ef [2] 80 f5 [2] 9e e8 [2] 9c e9 [2] 87 ef [2] 9b e8 [2] 87 c7 }

  condition:
    any of them
}