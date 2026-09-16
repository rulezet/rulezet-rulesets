rule TTP_XOR_MULT_DOSStub_47ff {
  strings:
    $key_47ff = { 13 97 [2] 67 8f [2] 20 8d [2] 67 9c [2] 29 90 [2] 25 9a [2] 32 91 [2] 29 df [2] 14 }

  condition:
    any of them
}