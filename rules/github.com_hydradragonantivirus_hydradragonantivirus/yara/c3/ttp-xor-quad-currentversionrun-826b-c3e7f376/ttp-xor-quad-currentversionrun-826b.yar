rule TTP_XOR_QUAD_CurrentVersionRun_826b {
  strings:
    $key_826b = { d1 04 [2] f5 0a [2] de 26 [2] f0 04 [2] e4 1f [2] eb 05 [2] f5 18 [2] f7 19 [2] ec 1f [2] f0 18 [2] ec 37 }

  condition:
    any of them
}