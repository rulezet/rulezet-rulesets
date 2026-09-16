rule TTP_XOR_MULT_DOSStub_65ff {
  strings:
    $key_65ff = { 31 97 [2] 45 8f [2] 02 8d [2] 45 9c [2] 0b 90 [2] 07 9a [2] 10 91 [2] 0b df [2] 36 }

  condition:
    any of them
}