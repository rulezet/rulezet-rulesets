rule TTP_XOR_MULT_DOSStub_850a {
  strings:
    $key_850a = { d1 62 [2] a5 7a [2] e2 78 [2] a5 69 [2] eb 65 [2] e7 6f [2] f0 64 [2] eb 2a [2] d6 }

  condition:
    any of them
}