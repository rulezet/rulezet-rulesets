rule TTP_XOR_QUAD_CurrentVersionRun_5d8c {
  strings:
    $key_5d8c = { 0e e3 [2] 2a ed [2] 01 c1 [2] 2f e3 [2] 3b f8 [2] 34 e2 [2] 2a ff [2] 28 fe [2] 33 f8 [2] 2f ff [2] 33 d0 }

  condition:
    any of them
}