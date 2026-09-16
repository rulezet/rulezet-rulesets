rule TTP_XOR_QUAD_CurrentVersionRun_389e {
  strings:
    $key_389e = { 6b f1 [2] 4f ff [2] 64 d3 [2] 4a f1 [2] 5e ea [2] 51 f0 [2] 4f ed [2] 4d ec [2] 56 ea [2] 4a ed [2] 56 c2 }

  condition:
    any of them
}