rule TTP_XOR_QUAD_CurrentVersionRun_f38c {
  strings:
    $key_f38c = { a0 e3 [2] 84 ed [2] af c1 [2] 81 e3 [2] 95 f8 [2] 9a e2 [2] 84 ff [2] 86 fe [2] 9d f8 [2] 81 ff [2] 9d d0 }

  condition:
    any of them
}