rule TTP_XOR_QUAD_CurrentVersionRun_289e {
  strings:
    $key_289e = { 7b f1 [2] 5f ff [2] 74 d3 [2] 5a f1 [2] 4e ea [2] 41 f0 [2] 5f ed [2] 5d ec [2] 46 ea [2] 5a ed [2] 46 c2 }

  condition:
    any of them
}