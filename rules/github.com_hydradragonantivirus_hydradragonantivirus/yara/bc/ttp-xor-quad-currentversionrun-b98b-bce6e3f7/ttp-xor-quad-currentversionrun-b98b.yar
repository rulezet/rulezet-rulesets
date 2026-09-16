rule TTP_XOR_QUAD_CurrentVersionRun_b98b {
  strings:
    $key_b98b = { ea e4 [2] ce ea [2] e5 c6 [2] cb e4 [2] df ff [2] d0 e5 [2] ce f8 [2] cc f9 [2] d7 ff [2] cb f8 [2] d7 d7 }

  condition:
    any of them
}