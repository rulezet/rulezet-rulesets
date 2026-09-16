rule TTP_XOR_MULT_DOSStub_10ff {
  strings:
    $key_10ff = { 44 97 [2] 30 8f [2] 77 8d [2] 30 9c [2] 7e 90 [2] 72 9a [2] 65 91 [2] 7e df [2] 43 }

  condition:
    any of them
}