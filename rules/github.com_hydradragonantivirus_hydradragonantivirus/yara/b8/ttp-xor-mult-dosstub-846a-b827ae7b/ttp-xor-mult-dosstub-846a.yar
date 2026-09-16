rule TTP_XOR_MULT_DOSStub_846a {
  strings:
    $key_846a = { d0 02 [2] a4 1a [2] e3 18 [2] a4 09 [2] ea 05 [2] e6 0f [2] f1 04 [2] ea 4a [2] d7 }

  condition:
    any of them
}