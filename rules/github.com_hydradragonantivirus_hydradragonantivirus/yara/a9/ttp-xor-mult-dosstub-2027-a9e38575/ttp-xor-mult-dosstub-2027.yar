rule TTP_XOR_MULT_DOSStub_2027 {
  strings:
    $key_2027 = { 74 4f [2] 00 57 [2] 47 55 [2] 00 44 [2] 4e 48 [2] 42 42 [2] 55 49 [2] 4e 07 [2] 73 }

  condition:
    any of them
}