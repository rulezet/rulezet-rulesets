rule TTP_XOR_QUAD_CurrentVersionRun_f69d {
  strings:
    $key_f69d = { a5 f2 [2] 81 fc [2] aa d0 [2] 84 f2 [2] 90 e9 [2] 9f f3 [2] 81 ee [2] 83 ef [2] 98 e9 [2] 84 ee [2] 98 c1 }

  condition:
    any of them
}