rule TTP_XOR_QUAD_CurrentVersionRun_f38d {
  strings:
    $key_f38d = { a0 e2 [2] 84 ec [2] af c0 [2] 81 e2 [2] 95 f9 [2] 9a e3 [2] 84 fe [2] 86 ff [2] 9d f9 [2] 81 fe [2] 9d d1 }

  condition:
    any of them
}