rule TTP_XOR_MULT_DOSStub_45ff {
  strings:
    $key_45ff = { 11 97 [2] 65 8f [2] 22 8d [2] 65 9c [2] 2b 90 [2] 27 9a [2] 30 91 [2] 2b df [2] 16 }

  condition:
    any of them
}