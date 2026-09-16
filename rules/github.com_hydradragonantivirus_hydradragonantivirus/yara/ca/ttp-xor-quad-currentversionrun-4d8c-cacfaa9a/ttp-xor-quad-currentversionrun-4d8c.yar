rule TTP_XOR_QUAD_CurrentVersionRun_4d8c {
  strings:
    $key_4d8c = { 1e e3 [2] 3a ed [2] 11 c1 [2] 3f e3 [2] 2b f8 [2] 24 e2 [2] 3a ff [2] 38 fe [2] 23 f8 [2] 3f ff [2] 23 d0 }

  condition:
    any of them
}