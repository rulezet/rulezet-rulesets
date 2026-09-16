rule TTP_XOR_QUAD_CurrentVersionRun_ccce {
  strings:
    $key_ccce = { 9f a1 [2] bb af [2] 90 83 [2] be a1 [2] aa ba [2] a5 a0 [2] bb bd [2] b9 bc [2] a2 ba [2] be bd [2] a2 92 }

  condition:
    any of them
}