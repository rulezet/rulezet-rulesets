rule TTP_XOR_MULT_DOSStub_39ff {
  strings:
    $key_39ff = { 6d 97 [2] 19 8f [2] 5e 8d [2] 19 9c [2] 57 90 [2] 5b 9a [2] 4c 91 [2] 57 df [2] 6a }

  condition:
    any of them
}