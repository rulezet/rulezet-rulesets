rule TTP_XOR_QUAD_CurrentVersionRun_5ace {
  strings:
    $key_5ace = { 09 a1 [2] 2d af [2] 06 83 [2] 28 a1 [2] 3c ba [2] 33 a0 [2] 2d bd [2] 2f bc [2] 34 ba [2] 28 bd [2] 34 92 }

  condition:
    any of them
}