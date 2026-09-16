rule TTP_XOR_QUAD_CurrentVersionRun_6d8c {
  strings:
    $key_6d8c = { 3e e3 [2] 1a ed [2] 31 c1 [2] 1f e3 [2] 0b f8 [2] 04 e2 [2] 1a ff [2] 18 fe [2] 03 f8 [2] 1f ff [2] 03 d0 }

  condition:
    any of them
}