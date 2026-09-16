rule TTP_XOR_QUAD_CurrentVersionRun_e3dd {
  strings:
    $key_e3dd = { b0 b2 [2] 94 bc [2] bf 90 [2] 91 b2 [2] 85 a9 [2] 8a b3 [2] 94 ae [2] 96 af [2] 8d a9 [2] 91 ae [2] 8d 81 }

  condition:
    any of them
}