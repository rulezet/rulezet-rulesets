rule TTP_XOR_QUAD_CurrentVersionRun_239b {
  strings:
    $key_239b = { 70 f4 [2] 54 fa [2] 7f d6 [2] 51 f4 [2] 45 ef [2] 4a f5 [2] 54 e8 [2] 56 e9 [2] 4d ef [2] 51 e8 [2] 4d c7 }

  condition:
    any of them
}