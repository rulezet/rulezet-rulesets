rule TTP_XOR_QUAD_CurrentVersionRun_499e {
  strings:
    $key_499e = { 1a f1 [2] 3e ff [2] 15 d3 [2] 3b f1 [2] 2f ea [2] 20 f0 [2] 3e ed [2] 3c ec [2] 27 ea [2] 3b ed [2] 27 c2 }

  condition:
    any of them
}