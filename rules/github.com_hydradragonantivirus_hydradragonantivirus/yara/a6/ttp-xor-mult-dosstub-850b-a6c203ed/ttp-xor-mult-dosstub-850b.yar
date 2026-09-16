rule TTP_XOR_MULT_DOSStub_850b {
  strings:
    $key_850b = { d1 63 [2] a5 7b [2] e2 79 [2] a5 68 [2] eb 64 [2] e7 6e [2] f0 65 [2] eb 2b [2] d6 }

  condition:
    any of them
}