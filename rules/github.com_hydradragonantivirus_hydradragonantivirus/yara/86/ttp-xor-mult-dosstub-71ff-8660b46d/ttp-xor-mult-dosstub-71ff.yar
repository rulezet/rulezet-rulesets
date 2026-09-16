rule TTP_XOR_MULT_DOSStub_71ff {
  strings:
    $key_71ff = { 25 97 [2] 51 8f [2] 16 8d [2] 51 9c [2] 1f 90 [2] 13 9a [2] 04 91 [2] 1f df [2] 22 }

  condition:
    any of them
}