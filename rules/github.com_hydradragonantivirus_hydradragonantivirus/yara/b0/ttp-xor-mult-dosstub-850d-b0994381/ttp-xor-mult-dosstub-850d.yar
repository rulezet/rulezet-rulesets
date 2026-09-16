rule TTP_XOR_MULT_DOSStub_850d {
  strings:
    $key_850d = { d1 65 [2] a5 7d [2] e2 7f [2] a5 6e [2] eb 62 [2] e7 68 [2] f0 63 [2] eb 2d [2] d6 }

  condition:
    any of them
}