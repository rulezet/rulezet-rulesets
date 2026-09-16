rule TTP_XOR_MULT_DOSStub_92ff {
  strings:
    $key_92ff = { c6 97 [2] b2 8f [2] f5 8d [2] b2 9c [2] fc 90 [2] f0 9a [2] e7 91 [2] fc df [2] c1 }

  condition:
    any of them
}