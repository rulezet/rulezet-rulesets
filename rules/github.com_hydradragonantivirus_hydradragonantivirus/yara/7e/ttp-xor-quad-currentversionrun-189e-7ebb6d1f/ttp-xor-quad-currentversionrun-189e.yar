rule TTP_XOR_QUAD_CurrentVersionRun_189e {
  strings:
    $key_189e = { 4b f1 [2] 6f ff [2] 44 d3 [2] 6a f1 [2] 7e ea [2] 71 f0 [2] 6f ed [2] 6d ec [2] 76 ea [2] 6a ed [2] 76 c2 }

  condition:
    any of them
}