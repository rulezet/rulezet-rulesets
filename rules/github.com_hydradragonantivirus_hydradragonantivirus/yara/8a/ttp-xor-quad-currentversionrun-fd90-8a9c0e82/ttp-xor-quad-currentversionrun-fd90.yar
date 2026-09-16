rule TTP_XOR_QUAD_CurrentVersionRun_fd90 {
  strings:
    $key_fd90 = { ae ff [2] 8a f1 [2] a1 dd [2] 8f ff [2] 9b e4 [2] 94 fe [2] 8a e3 [2] 88 e2 [2] 93 e4 [2] 8f e3 [2] 93 cc }

  condition:
    any of them
}