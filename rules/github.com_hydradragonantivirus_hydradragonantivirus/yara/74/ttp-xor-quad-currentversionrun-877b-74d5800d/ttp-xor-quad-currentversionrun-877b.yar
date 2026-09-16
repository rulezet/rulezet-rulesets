rule TTP_XOR_QUAD_CurrentVersionRun_877b {
  strings:
    $key_877b = { d4 14 [2] f0 1a [2] db 36 [2] f5 14 [2] e1 0f [2] ee 15 [2] f0 08 [2] f2 09 [2] e9 0f [2] f5 08 [2] e9 27 }

  condition:
    any of them
}