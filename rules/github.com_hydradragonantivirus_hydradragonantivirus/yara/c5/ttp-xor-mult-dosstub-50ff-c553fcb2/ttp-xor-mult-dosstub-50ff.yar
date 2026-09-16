rule TTP_XOR_MULT_DOSStub_50ff {
  strings:
    $key_50ff = { 04 97 [2] 70 8f [2] 37 8d [2] 70 9c [2] 3e 90 [2] 32 9a [2] 25 91 [2] 3e df [2] 03 }

  condition:
    any of them
}