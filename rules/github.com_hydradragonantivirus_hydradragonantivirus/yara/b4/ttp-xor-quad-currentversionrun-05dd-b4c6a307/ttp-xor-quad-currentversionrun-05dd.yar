rule TTP_XOR_QUAD_CurrentVersionRun_05dd {
  strings:
    $key_05dd = { 56 b2 [2] 72 bc [2] 59 90 [2] 77 b2 [2] 63 a9 [2] 6c b3 [2] 72 ae [2] 70 af [2] 6b a9 [2] 77 ae [2] 6b 81 }

  condition:
    any of them
}