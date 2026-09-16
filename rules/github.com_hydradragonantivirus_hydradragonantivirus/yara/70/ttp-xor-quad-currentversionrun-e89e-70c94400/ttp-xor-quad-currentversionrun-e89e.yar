rule TTP_XOR_QUAD_CurrentVersionRun_e89e {
  strings:
    $key_e89e = { bb f1 [2] 9f ff [2] b4 d3 [2] 9a f1 [2] 8e ea [2] 81 f0 [2] 9f ed [2] 9d ec [2] 86 ea [2] 9a ed [2] 86 c2 }

  condition:
    any of them
}