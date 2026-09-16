rule TTP_XOR_QUAD_CurrentVersionRun_689e {
  strings:
    $key_689e = { 3b f1 [2] 1f ff [2] 34 d3 [2] 1a f1 [2] 0e ea [2] 01 f0 [2] 1f ed [2] 1d ec [2] 06 ea [2] 1a ed [2] 06 c2 }

  condition:
    any of them
}