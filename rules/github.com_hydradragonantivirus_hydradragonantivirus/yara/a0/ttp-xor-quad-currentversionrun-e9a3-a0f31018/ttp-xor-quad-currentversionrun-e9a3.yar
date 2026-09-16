rule TTP_XOR_QUAD_CurrentVersionRun_e9a3 {
  strings:
    $key_e9a3 = { ba cc [2] 9e c2 [2] b5 ee [2] 9b cc [2] 8f d7 [2] 80 cd [2] 9e d0 [2] 9c d1 [2] 87 d7 [2] 9b d0 [2] 87 ff }

  condition:
    any of them
}