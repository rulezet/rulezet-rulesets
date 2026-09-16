rule TTP_XOR_MULT_DOSStub_46ff {
  strings:
    $key_46ff = { 12 97 [2] 66 8f [2] 21 8d [2] 66 9c [2] 28 90 [2] 24 9a [2] 33 91 [2] 28 df [2] 15 }

  condition:
    any of them
}