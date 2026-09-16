rule TTP_XOR_MULT_DOSStub_64ff {
  strings:
    $key_64ff = { 30 97 [2] 44 8f [2] 03 8d [2] 44 9c [2] 0a 90 [2] 06 9a [2] 11 91 [2] 0a df [2] 37 }

  condition:
    any of them
}