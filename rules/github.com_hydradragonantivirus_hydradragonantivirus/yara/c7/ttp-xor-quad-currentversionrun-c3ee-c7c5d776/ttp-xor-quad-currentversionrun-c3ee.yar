rule TTP_XOR_QUAD_CurrentVersionRun_c3ee {
  strings:
    $key_c3ee = { 90 81 [2] b4 8f [2] 9f a3 [2] b1 81 [2] a5 9a [2] aa 80 [2] b4 9d [2] b6 9c [2] ad 9a [2] b1 9d [2] ad b2 }

  condition:
    any of them
}