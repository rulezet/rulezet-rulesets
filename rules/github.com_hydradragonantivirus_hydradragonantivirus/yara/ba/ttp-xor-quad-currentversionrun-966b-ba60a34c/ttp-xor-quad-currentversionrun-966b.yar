rule TTP_XOR_QUAD_CurrentVersionRun_966b {
  strings:
    $key_966b = { c5 04 [2] e1 0a [2] ca 26 [2] e4 04 [2] f0 1f [2] ff 05 [2] e1 18 [2] e3 19 [2] f8 1f [2] e4 18 [2] f8 37 }

  condition:
    any of them
}