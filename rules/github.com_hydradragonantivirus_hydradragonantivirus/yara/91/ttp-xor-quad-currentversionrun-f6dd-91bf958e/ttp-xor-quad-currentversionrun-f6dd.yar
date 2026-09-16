rule TTP_XOR_QUAD_CurrentVersionRun_f6dd {
  strings:
    $key_f6dd = { a5 b2 [2] 81 bc [2] aa 90 [2] 84 b2 [2] 90 a9 [2] 9f b3 [2] 81 ae [2] 83 af [2] 98 a9 [2] 84 ae [2] 98 81 }

  condition:
    any of them
}