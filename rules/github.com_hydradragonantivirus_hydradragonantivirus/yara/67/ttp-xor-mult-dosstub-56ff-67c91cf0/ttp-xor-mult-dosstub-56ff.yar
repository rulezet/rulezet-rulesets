rule TTP_XOR_MULT_DOSStub_56ff {
  strings:
    $key_56ff = { 02 97 [2] 76 8f [2] 31 8d [2] 76 9c [2] 38 90 [2] 34 9a [2] 23 91 [2] 38 df [2] 05 }

  condition:
    any of them
}