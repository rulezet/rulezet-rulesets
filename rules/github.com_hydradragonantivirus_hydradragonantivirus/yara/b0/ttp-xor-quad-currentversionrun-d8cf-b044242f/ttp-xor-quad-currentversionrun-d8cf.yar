rule TTP_XOR_QUAD_CurrentVersionRun_d8cf {
  strings:
    $key_d8cf = { 8b a0 [2] af ae [2] 84 82 [2] aa a0 [2] be bb [2] b1 a1 [2] af bc [2] ad bd [2] b6 bb [2] aa bc [2] b6 93 }

  condition:
    any of them
}