rule TTP_XOR_QUAD_CurrentVersionRun_c4ce {
  strings:
    $key_c4ce = { 97 a1 [2] b3 af [2] 98 83 [2] b6 a1 [2] a2 ba [2] ad a0 [2] b3 bd [2] b1 bc [2] aa ba [2] b6 bd [2] aa 92 }

  condition:
    any of them
}