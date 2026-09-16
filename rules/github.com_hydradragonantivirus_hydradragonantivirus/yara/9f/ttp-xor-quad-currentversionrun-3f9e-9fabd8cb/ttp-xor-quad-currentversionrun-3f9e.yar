rule TTP_XOR_QUAD_CurrentVersionRun_3f9e {
  strings:
    $key_3f9e = { 6c f1 [2] 48 ff [2] 63 d3 [2] 4d f1 [2] 59 ea [2] 56 f0 [2] 48 ed [2] 4a ec [2] 51 ea [2] 4d ed [2] 51 c2 }

  condition:
    any of them
}