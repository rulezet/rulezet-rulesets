rule TTP_XOR_MULT_DOSStub_60ff {
  strings:
    $key_60ff = { 34 97 [2] 40 8f [2] 07 8d [2] 40 9c [2] 0e 90 [2] 02 9a [2] 15 91 [2] 0e df [2] 33 }

  condition:
    any of them
}