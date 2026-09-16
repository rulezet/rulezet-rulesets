rule TTP_XOR_QUAD_CurrentVersionRun_e99e {
  strings:
    $key_e99e = { ba f1 [2] 9e ff [2] b5 d3 [2] 9b f1 [2] 8f ea [2] 80 f0 [2] 9e ed [2] 9c ec [2] 87 ea [2] 9b ed [2] 87 c2 }

  condition:
    any of them
}