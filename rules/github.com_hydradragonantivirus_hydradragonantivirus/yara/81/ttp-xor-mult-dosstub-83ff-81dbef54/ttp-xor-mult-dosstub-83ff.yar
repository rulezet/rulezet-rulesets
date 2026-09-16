rule TTP_XOR_MULT_DOSStub_83ff {
  strings:
    $key_83ff = { d7 97 [2] a3 8f [2] e4 8d [2] a3 9c [2] ed 90 [2] e1 9a [2] f6 91 [2] ed df [2] d0 }

  condition:
    any of them
}