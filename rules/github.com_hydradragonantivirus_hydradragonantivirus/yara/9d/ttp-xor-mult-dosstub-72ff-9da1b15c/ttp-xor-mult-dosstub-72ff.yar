rule TTP_XOR_MULT_DOSStub_72ff {
  strings:
    $key_72ff = { 26 97 [2] 52 8f [2] 15 8d [2] 52 9c [2] 1c 90 [2] 10 9a [2] 07 91 [2] 1c df [2] 21 }

  condition:
    any of them
}