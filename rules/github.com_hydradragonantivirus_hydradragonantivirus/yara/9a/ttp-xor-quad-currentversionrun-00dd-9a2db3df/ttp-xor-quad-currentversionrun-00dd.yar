rule TTP_XOR_QUAD_CurrentVersionRun_00dd {
  strings:
    $key_00dd = { 53 b2 [2] 77 bc [2] 5c 90 [2] 72 b2 [2] 66 a9 [2] 69 b3 [2] 77 ae [2] 75 af [2] 6e a9 [2] 72 ae [2] 6e 81 }

  condition:
    any of them
}