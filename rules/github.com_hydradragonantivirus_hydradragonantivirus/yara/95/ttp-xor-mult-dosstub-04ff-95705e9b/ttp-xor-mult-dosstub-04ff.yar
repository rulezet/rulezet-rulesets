rule TTP_XOR_MULT_DOSStub_04ff {
  strings:
    $key_04ff = { 50 97 [2] 24 8f [2] 63 8d [2] 24 9c [2] 6a 90 [2] 66 9a [2] 71 91 [2] 6a df [2] 57 }

  condition:
    any of them
}