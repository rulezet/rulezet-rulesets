rule TTP_XOR_QUAD_CurrentVersionRun_961b {
  strings:
    $key_961b = { c5 74 [2] e1 7a [2] ca 56 [2] e4 74 [2] f0 6f [2] ff 75 [2] e1 68 [2] e3 69 [2] f8 6f [2] e4 68 [2] f8 47 }

  condition:
    any of them
}