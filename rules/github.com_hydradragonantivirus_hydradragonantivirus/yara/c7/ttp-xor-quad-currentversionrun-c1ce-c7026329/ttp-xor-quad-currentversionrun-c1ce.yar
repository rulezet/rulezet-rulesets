rule TTP_XOR_QUAD_CurrentVersionRun_c1ce {
  strings:
    $key_c1ce = { 92 a1 [2] b6 af [2] 9d 83 [2] b3 a1 [2] a7 ba [2] a8 a0 [2] b6 bd [2] b4 bc [2] af ba [2] b3 bd [2] af 92 }

  condition:
    any of them
}