rule TTP_XOR_MULT_DOSStub_42ff {
  strings:
    $key_42ff = { 16 97 [2] 62 8f [2] 25 8d [2] 62 9c [2] 2c 90 [2] 20 9a [2] 37 91 [2] 2c df [2] 11 }

  condition:
    any of them
}