rule TTP_XOR_QUAD_CurrentVersionRun_368c {
  strings:
    $key_368c = { 65 e3 [2] 41 ed [2] 6a c1 [2] 44 e3 [2] 50 f8 [2] 5f e2 [2] 41 ff [2] 43 fe [2] 58 f8 [2] 44 ff [2] 58 d0 }

  condition:
    any of them
}