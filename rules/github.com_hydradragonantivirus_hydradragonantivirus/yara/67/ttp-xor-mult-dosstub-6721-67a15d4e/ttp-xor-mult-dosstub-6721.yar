rule TTP_XOR_MULT_DOSStub_6721 {
  strings:
    $key_6721 = { 33 49 [2] 47 51 [2] 00 53 [2] 47 42 [2] 09 4e [2] 05 44 [2] 12 4f [2] 09 01 [2] 34 }

  condition:
    any of them
}