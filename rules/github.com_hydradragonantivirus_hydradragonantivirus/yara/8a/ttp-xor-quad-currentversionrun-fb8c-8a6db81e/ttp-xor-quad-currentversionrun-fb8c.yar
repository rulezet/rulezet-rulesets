rule TTP_XOR_QUAD_CurrentVersionRun_fb8c {
  strings:
    $key_fb8c = { a8 e3 [2] 8c ed [2] a7 c1 [2] 89 e3 [2] 9d f8 [2] 92 e2 [2] 8c ff [2] 8e fe [2] 95 f8 [2] 89 ff [2] 95 d0 }

  condition:
    any of them
}