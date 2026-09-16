rule TTP_XOR_MULT_DOSStub_20ff {
  strings:
    $key_20ff = { 74 97 [2] 00 8f [2] 47 8d [2] 00 9c [2] 4e 90 [2] 42 9a [2] 55 91 [2] 4e df [2] 73 }

  condition:
    any of them
}