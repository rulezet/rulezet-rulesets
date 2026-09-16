rule TTP_XOR_MULT_DOSStub_52ff {
  strings:
    $key_52ff = { 06 97 [2] 72 8f [2] 35 8d [2] 72 9c [2] 3c 90 [2] 30 9a [2] 27 91 [2] 3c df [2] 01 }

  condition:
    any of them
}