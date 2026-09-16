rule TTP_XOR_QUAD_CurrentVersionRun_199e {
  strings:
    $key_199e = { 4a f1 [2] 6e ff [2] 45 d3 [2] 6b f1 [2] 7f ea [2] 70 f0 [2] 6e ed [2] 6c ec [2] 77 ea [2] 6b ed [2] 77 c2 }

  condition:
    any of them
}