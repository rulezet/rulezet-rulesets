rule TTP_XOR_MULT_DOSStub_49ff {
  strings:
    $key_49ff = { 1d 97 [2] 69 8f [2] 2e 8d [2] 69 9c [2] 27 90 [2] 2b 9a [2] 3c 91 [2] 27 df [2] 1a }

  condition:
    any of them
}