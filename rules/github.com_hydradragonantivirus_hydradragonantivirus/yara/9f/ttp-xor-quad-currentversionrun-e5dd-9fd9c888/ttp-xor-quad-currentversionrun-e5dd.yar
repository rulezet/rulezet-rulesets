rule TTP_XOR_QUAD_CurrentVersionRun_e5dd {
  strings:
    $key_e5dd = { b6 b2 [2] 92 bc [2] b9 90 [2] 97 b2 [2] 83 a9 [2] 8c b3 [2] 92 ae [2] 90 af [2] 8b a9 [2] 97 ae [2] 8b 81 }

  condition:
    any of them
}