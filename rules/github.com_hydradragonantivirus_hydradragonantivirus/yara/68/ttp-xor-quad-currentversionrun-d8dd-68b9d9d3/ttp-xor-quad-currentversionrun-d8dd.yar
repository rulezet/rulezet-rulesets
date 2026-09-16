rule TTP_XOR_QUAD_CurrentVersionRun_d8dd {
  strings:
    $key_d8dd = { 8b b2 [2] af bc [2] 84 90 [2] aa b2 [2] be a9 [2] b1 b3 [2] af ae [2] ad af [2] b6 a9 [2] aa ae [2] b6 81 }

  condition:
    any of them
}