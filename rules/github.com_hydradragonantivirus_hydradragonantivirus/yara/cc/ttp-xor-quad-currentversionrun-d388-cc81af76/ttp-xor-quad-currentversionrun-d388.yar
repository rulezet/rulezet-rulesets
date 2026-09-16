rule TTP_XOR_QUAD_CurrentVersionRun_d388 {
  strings:
    $key_d388 = { 80 e7 [2] a4 e9 [2] 8f c5 [2] a1 e7 [2] b5 fc [2] ba e6 [2] a4 fb [2] a6 fa [2] bd fc [2] a1 fb [2] bd d4 }

  condition:
    any of them
}