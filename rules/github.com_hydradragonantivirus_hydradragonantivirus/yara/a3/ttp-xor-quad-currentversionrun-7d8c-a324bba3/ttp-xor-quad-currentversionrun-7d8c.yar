rule TTP_XOR_QUAD_CurrentVersionRun_7d8c {
  strings:
    $key_7d8c = { 2e e3 [2] 0a ed [2] 21 c1 [2] 0f e3 [2] 1b f8 [2] 14 e2 [2] 0a ff [2] 08 fe [2] 13 f8 [2] 0f ff [2] 13 d0 }

  condition:
    any of them
}