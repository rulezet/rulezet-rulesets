rule TTP_XOR_QUAD_CurrentVersionRun_019d {
  strings:
    $key_019d = { 52 f2 [2] 76 fc [2] 5d d0 [2] 73 f2 [2] 67 e9 [2] 68 f3 [2] 76 ee [2] 74 ef [2] 6f e9 [2] 73 ee [2] 6f c1 }

  condition:
    any of them
}