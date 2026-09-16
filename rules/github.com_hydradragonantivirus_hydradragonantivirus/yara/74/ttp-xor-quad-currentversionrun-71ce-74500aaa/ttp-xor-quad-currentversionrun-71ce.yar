rule TTP_XOR_QUAD_CurrentVersionRun_71ce {
  strings:
    $key_71ce = { 22 a1 [2] 06 af [2] 2d 83 [2] 03 a1 [2] 17 ba [2] 18 a0 [2] 06 bd [2] 04 bc [2] 1f ba [2] 03 bd [2] 1f 92 }

  condition:
    any of them
}