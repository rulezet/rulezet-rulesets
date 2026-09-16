rule TTP_XOR_MULT_DOSStub_97ff {
  strings:
    $key_97ff = { c3 97 [2] b7 8f [2] f0 8d [2] b7 9c [2] f9 90 [2] f5 9a [2] e2 91 [2] f9 df [2] c4 }

  condition:
    any of them
}