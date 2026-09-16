rule TTP_XOR_QUAD_CurrentVersionRun_967b {
  strings:
    $key_967b = { c5 14 [2] e1 1a [2] ca 36 [2] e4 14 [2] f0 0f [2] ff 15 [2] e1 08 [2] e3 09 [2] f8 0f [2] e4 08 [2] f8 27 }

  condition:
    any of them
}