rule TTP_XOR_QUAD_CurrentVersionRun_e28c {
  strings:
    $key_e28c = { b1 e3 [2] 95 ed [2] be c1 [2] 90 e3 [2] 84 f8 [2] 8b e2 [2] 95 ff [2] 97 fe [2] 8c f8 [2] 90 ff [2] 8c d0 }

  condition:
    any of them
}