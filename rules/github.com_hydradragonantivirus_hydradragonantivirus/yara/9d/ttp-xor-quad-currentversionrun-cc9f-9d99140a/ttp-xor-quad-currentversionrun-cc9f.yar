rule TTP_XOR_QUAD_CurrentVersionRun_cc9f {
  strings:
    $key_cc9f = { 9f f0 [2] bb fe [2] 90 d2 [2] be f0 [2] aa eb [2] a5 f1 [2] bb ec [2] b9 ed [2] a2 eb [2] be ec [2] a2 c3 }

  condition:
    any of them
}