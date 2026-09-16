rule TTP_XOR_MULT_DOSStub_863b {
  strings:
    $key_863b = { d2 53 [2] a6 4b [2] e1 49 [2] a6 58 [2] e8 54 [2] e4 5e [2] f3 55 [2] e8 1b [2] d5 }

  condition:
    any of them
}