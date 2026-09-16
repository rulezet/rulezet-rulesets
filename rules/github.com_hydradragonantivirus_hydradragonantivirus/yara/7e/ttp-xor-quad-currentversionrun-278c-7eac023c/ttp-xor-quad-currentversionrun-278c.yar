rule TTP_XOR_QUAD_CurrentVersionRun_278c {
  strings:
    $key_278c = { 74 e3 [2] 50 ed [2] 7b c1 [2] 55 e3 [2] 41 f8 [2] 4e e2 [2] 50 ff [2] 52 fe [2] 49 f8 [2] 55 ff [2] 49 d0 }

  condition:
    any of them
}