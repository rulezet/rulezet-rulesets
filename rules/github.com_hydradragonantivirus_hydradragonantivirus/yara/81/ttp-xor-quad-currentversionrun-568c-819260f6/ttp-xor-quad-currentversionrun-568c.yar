rule TTP_XOR_QUAD_CurrentVersionRun_568c {
  strings:
    $key_568c = { 05 e3 [2] 21 ed [2] 0a c1 [2] 24 e3 [2] 30 f8 [2] 3f e2 [2] 21 ff [2] 23 fe [2] 38 f8 [2] 24 ff [2] 38 d0 }

  condition:
    any of them
}