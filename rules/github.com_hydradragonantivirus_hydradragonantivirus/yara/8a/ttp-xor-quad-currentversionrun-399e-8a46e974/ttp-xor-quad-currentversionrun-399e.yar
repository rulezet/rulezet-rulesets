rule TTP_XOR_QUAD_CurrentVersionRun_399e {
  strings:
    $key_399e = { 6a f1 [2] 4e ff [2] 65 d3 [2] 4b f1 [2] 5f ea [2] 50 f0 [2] 4e ed [2] 4c ec [2] 57 ea [2] 4b ed [2] 57 c2 }

  condition:
    any of them
}