rule TTP_XOR_MULT_DOSStub_67ff {
  strings:
    $key_67ff = { 33 97 [2] 47 8f [2] 00 8d [2] 47 9c [2] 09 90 [2] 05 9a [2] 12 91 [2] 09 df [2] 34 }

  condition:
    any of them
}