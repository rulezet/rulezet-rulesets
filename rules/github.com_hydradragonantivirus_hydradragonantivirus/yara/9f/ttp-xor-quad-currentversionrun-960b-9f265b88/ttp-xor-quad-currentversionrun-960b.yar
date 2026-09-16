rule TTP_XOR_QUAD_CurrentVersionRun_960b {
  strings:
    $key_960b = { c5 64 [2] e1 6a [2] ca 46 [2] e4 64 [2] f0 7f [2] ff 65 [2] e1 78 [2] e3 79 [2] f8 7f [2] e4 78 [2] f8 57 }

  condition:
    any of them
}