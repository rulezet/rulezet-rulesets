rule TTP_XOR_QUAD_CurrentVersionRun_f69e {
  strings:
    $key_f69e = { a5 f1 [2] 81 ff [2] aa d3 [2] 84 f1 [2] 90 ea [2] 9f f0 [2] 81 ed [2] 83 ec [2] 98 ea [2] 84 ed [2] 98 c2 }

  condition:
    any of them
}