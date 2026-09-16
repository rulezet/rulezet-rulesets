rule TTP_XOR_QUAD_CurrentVersionRun_e48c {
  strings:
    $key_e48c = { b7 e3 [2] 93 ed [2] b8 c1 [2] 96 e3 [2] 82 f8 [2] 8d e2 [2] 93 ff [2] 91 fe [2] 8a f8 [2] 96 ff [2] 8a d0 }

  condition:
    any of them
}