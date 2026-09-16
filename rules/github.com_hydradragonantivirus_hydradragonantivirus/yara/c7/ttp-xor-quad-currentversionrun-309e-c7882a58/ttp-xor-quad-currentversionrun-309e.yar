rule TTP_XOR_QUAD_CurrentVersionRun_309e {
  strings:
    $key_309e = { 63 f1 [2] 47 ff [2] 6c d3 [2] 42 f1 [2] 56 ea [2] 59 f0 [2] 47 ed [2] 45 ec [2] 5e ea [2] 42 ed [2] 5e c2 }

  condition:
    any of them
}