rule TTP_XOR_QUAD_CurrentVersionRun_e48d {
  strings:
    $key_e48d = { b7 e2 [2] 93 ec [2] b8 c0 [2] 96 e2 [2] 82 f9 [2] 8d e3 [2] 93 fe [2] 91 ff [2] 8a f9 [2] 96 fe [2] 8a d1 }

  condition:
    any of them
}