rule TTP_XOR_MULT_DOSStub_77ff {
  strings:
    $key_77ff = { 23 97 [2] 57 8f [2] 10 8d [2] 57 9c [2] 19 90 [2] 15 9a [2] 02 91 [2] 19 df [2] 24 }

  condition:
    any of them
}