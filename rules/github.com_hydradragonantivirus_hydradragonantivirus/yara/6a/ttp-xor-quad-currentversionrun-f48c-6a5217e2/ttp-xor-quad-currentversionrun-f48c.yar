rule TTP_XOR_QUAD_CurrentVersionRun_f48c {
  strings:
    $key_f48c = { a7 e3 [2] 83 ed [2] a8 c1 [2] 86 e3 [2] 92 f8 [2] 9d e2 [2] 83 ff [2] 81 fe [2] 9a f8 [2] 86 ff [2] 9a d0 }

  condition:
    any of them
}