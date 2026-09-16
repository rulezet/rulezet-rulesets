rule TTP_XOR_MULT_DOSStub_1821 {
  strings:
    $key_1821 = { 4c 49 [2] 38 51 [2] 7f 53 [2] 38 42 [2] 76 4e [2] 7a 44 [2] 6d 4f [2] 76 01 [2] 4b }

  condition:
    any of them
}