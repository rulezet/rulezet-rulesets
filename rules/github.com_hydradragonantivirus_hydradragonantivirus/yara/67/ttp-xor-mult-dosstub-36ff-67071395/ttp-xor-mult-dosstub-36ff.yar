rule TTP_XOR_MULT_DOSStub_36ff {
  strings:
    $key_36ff = { 62 97 [2] 16 8f [2] 51 8d [2] 16 9c [2] 58 90 [2] 54 9a [2] 43 91 [2] 58 df [2] 65 }

  condition:
    any of them
}