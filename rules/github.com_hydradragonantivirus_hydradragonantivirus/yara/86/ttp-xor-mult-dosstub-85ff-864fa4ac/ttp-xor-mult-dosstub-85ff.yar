rule TTP_XOR_MULT_DOSStub_85ff {
  strings:
    $key_85ff = { d1 97 [2] a5 8f [2] e2 8d [2] a5 9c [2] eb 90 [2] e7 9a [2] f0 91 [2] eb df [2] d6 }

  condition:
    any of them
}