rule TTP_XOR_QUAD_CurrentVersionRun_e490 {
  strings:
    $key_e490 = { b7 ff [2] 93 f1 [2] b8 dd [2] 96 ff [2] 82 e4 [2] 8d fe [2] 93 e3 [2] 91 e2 [2] 8a e4 [2] 96 e3 [2] 8a cc }

  condition:
    any of them
}