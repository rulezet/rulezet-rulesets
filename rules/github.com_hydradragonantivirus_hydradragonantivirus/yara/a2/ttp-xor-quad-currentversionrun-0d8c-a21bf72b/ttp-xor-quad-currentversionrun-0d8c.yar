rule TTP_XOR_QUAD_CurrentVersionRun_0d8c {
  strings:
    $key_0d8c = { 5e e3 [2] 7a ed [2] 51 c1 [2] 7f e3 [2] 6b f8 [2] 64 e2 [2] 7a ff [2] 78 fe [2] 63 f8 [2] 7f ff [2] 63 d0 }

  condition:
    any of them
}