rule TTP_XOR_MULT_DOSStub_833a {
  strings:
    $key_833a = { d7 52 [2] a3 4a [2] e4 48 [2] a3 59 [2] ed 55 [2] e1 5f [2] f6 54 [2] ed 1a [2] d0 }

  condition:
    any of them
}