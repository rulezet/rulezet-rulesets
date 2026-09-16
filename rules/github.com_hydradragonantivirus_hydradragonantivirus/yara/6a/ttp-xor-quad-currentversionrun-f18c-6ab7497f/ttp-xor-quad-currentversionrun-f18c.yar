rule TTP_XOR_QUAD_CurrentVersionRun_f18c {
  strings:
    $key_f18c = { a2 e3 [2] 86 ed [2] ad c1 [2] 83 e3 [2] 97 f8 [2] 98 e2 [2] 86 ff [2] 84 fe [2] 9f f8 [2] 83 ff [2] 9f d0 }

  condition:
    any of them
}