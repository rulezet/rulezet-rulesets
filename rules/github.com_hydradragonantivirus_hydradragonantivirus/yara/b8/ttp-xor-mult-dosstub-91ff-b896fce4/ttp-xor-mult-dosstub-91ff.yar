rule TTP_XOR_MULT_DOSStub_91ff {
  strings:
    $key_91ff = { c5 97 [2] b1 8f [2] f6 8d [2] b1 9c [2] ff 90 [2] f3 9a [2] e4 91 [2] ff df [2] c2 }

  condition:
    any of them
}