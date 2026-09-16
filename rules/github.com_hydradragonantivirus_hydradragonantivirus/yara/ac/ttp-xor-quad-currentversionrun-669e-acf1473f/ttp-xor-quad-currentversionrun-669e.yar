rule TTP_XOR_QUAD_CurrentVersionRun_669e {
  strings:
    $key_669e = { 35 f1 [2] 11 ff [2] 3a d3 [2] 14 f1 [2] 00 ea [2] 0f f0 [2] 11 ed [2] 13 ec [2] 08 ea [2] 14 ed [2] 08 c2 }

  condition:
    any of them
}