rule TTP_XOR_QUAD_CurrentVersionRun_89c0 {
  strings:
    $key_89c0 = { da af [2] fe a1 [2] d5 8d [2] fb af [2] ef b4 [2] e0 ae [2] fe b3 [2] fc b2 [2] e7 b4 [2] fb b3 [2] e7 9c }

  condition:
    any of them
}