rule TTP_XOR_MULT_DOSStub_66ff {
  strings:
    $key_66ff = { 32 97 [2] 46 8f [2] 01 8d [2] 46 9c [2] 08 90 [2] 04 9a [2] 13 91 [2] 08 df [2] 35 }

  condition:
    any of them
}