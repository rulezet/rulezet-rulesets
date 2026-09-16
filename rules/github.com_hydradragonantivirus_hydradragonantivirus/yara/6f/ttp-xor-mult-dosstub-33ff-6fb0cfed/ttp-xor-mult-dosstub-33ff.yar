rule TTP_XOR_MULT_DOSStub_33ff {
  strings:
    $key_33ff = { 67 97 [2] 13 8f [2] 54 8d [2] 13 9c [2] 5d 90 [2] 51 9a [2] 46 91 [2] 5d df [2] 60 }

  condition:
    any of them
}