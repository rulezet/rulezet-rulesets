rule TTP_XOR_MULT_DOSStub_25ff {
  strings:
    $key_25ff = { 71 97 [2] 05 8f [2] 42 8d [2] 05 9c [2] 4b 90 [2] 47 9a [2] 50 91 [2] 4b df [2] 76 }

  condition:
    any of them
}