rule TTP_XOR_QUAD_CurrentVersionRun_89c1 {
  strings:
    $key_89c1 = { da ae [2] fe a0 [2] d5 8c [2] fb ae [2] ef b5 [2] e0 af [2] fe b2 [2] fc b3 [2] e7 b5 [2] fb b2 [2] e7 9d }

  condition:
    any of them
}