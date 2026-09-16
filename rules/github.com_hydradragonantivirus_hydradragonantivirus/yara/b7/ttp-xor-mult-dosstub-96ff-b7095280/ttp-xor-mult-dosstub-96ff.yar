rule TTP_XOR_MULT_DOSStub_96ff {
  strings:
    $key_96ff = { c2 97 [2] b6 8f [2] f1 8d [2] b6 9c [2] f8 90 [2] f4 9a [2] e3 91 [2] f8 df [2] c5 }

  condition:
    any of them
}