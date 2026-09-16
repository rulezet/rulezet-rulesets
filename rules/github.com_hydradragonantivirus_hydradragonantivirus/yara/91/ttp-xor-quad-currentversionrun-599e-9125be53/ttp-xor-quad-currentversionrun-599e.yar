rule TTP_XOR_QUAD_CurrentVersionRun_599e {
  strings:
    $key_599e = { 0a f1 [2] 2e ff [2] 05 d3 [2] 2b f1 [2] 3f ea [2] 30 f0 [2] 2e ed [2] 2c ec [2] 37 ea [2] 2b ed [2] 37 c2 }

  condition:
    any of them
}