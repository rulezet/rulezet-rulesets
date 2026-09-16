rule TTP_XOR_QUAD_CurrentVersionRun_fb9d {
  strings:
    $key_fb9d = { a8 f2 [2] 8c fc [2] a7 d0 [2] 89 f2 [2] 9d e9 [2] 92 f3 [2] 8c ee [2] 8e ef [2] 95 e9 [2] 89 ee [2] 95 c1 }

  condition:
    any of them
}