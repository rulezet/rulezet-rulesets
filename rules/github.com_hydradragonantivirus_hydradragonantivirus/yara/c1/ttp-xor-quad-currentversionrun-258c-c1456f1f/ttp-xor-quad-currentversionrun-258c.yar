rule TTP_XOR_QUAD_CurrentVersionRun_258c {
  strings:
    $key_258c = { 76 e3 [2] 52 ed [2] 79 c1 [2] 57 e3 [2] 43 f8 [2] 4c e2 [2] 52 ff [2] 50 fe [2] 4b f8 [2] 57 ff [2] 4b d0 }

  condition:
    any of them
}