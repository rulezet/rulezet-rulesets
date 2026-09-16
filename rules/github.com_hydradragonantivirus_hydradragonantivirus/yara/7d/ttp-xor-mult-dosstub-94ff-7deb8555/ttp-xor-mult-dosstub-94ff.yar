rule TTP_XOR_MULT_DOSStub_94ff {
  strings:
    $key_94ff = { c0 97 [2] b4 8f [2] f3 8d [2] b4 9c [2] fa 90 [2] f6 9a [2] e1 91 [2] fa df [2] c7 }

  condition:
    any of them
}