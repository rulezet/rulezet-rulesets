rule TTP_XOR_MULT_DOSStub_54ff {
  strings:
    $key_54ff = { 00 97 [2] 74 8f [2] 33 8d [2] 74 9c [2] 3a 90 [2] 36 9a [2] 21 91 [2] 3a df [2] 07 }

  condition:
    any of them
}