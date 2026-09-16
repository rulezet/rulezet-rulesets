rule TTP_XOR_MULT_DOSStub_b0ff {
  strings:
    $key_b0ff = { e4 97 [2] 90 8f [2] d7 8d [2] 90 9c [2] de 90 [2] d2 9a [2] c5 91 [2] de df [2] e3 }

  condition:
    any of them
}