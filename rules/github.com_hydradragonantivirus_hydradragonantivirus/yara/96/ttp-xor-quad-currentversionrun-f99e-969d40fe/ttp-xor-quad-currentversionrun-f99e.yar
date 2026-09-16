rule TTP_XOR_QUAD_CurrentVersionRun_f99e {
  strings:
    $key_f99e = { aa f1 [2] 8e ff [2] a5 d3 [2] 8b f1 [2] 9f ea [2] 90 f0 [2] 8e ed [2] 8c ec [2] 97 ea [2] 8b ed [2] 97 c2 }

  condition:
    any of them
}