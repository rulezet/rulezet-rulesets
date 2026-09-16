rule TTP_XOR_QUAD_CurrentVersionRun_0ace {
  strings:
    $key_0ace = { 59 a1 [2] 7d af [2] 56 83 [2] 78 a1 [2] 6c ba [2] 63 a0 [2] 7d bd [2] 7f bc [2] 64 ba [2] 78 bd [2] 64 92 }

  condition:
    any of them
}