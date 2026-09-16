rule TTP_XOR_QUAD_CurrentVersionRun_ef9d {
  strings:
    $key_ef9d = { bc f2 [2] 98 fc [2] b3 d0 [2] 9d f2 [2] 89 e9 [2] 86 f3 [2] 98 ee [2] 9a ef [2] 81 e9 [2] 9d ee [2] 81 c1 }

  condition:
    any of them
}