rule TTP_XOR_QUAD_CurrentVersionRun_e09e {
  strings:
    $key_e09e = { b3 f1 [2] 97 ff [2] bc d3 [2] 92 f1 [2] 86 ea [2] 89 f0 [2] 97 ed [2] 95 ec [2] 8e ea [2] 92 ed [2] 8e c2 }

  condition:
    any of them
}