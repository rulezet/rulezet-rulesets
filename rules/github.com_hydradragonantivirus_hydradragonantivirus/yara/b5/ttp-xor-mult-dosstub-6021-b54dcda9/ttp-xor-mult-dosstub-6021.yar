rule TTP_XOR_MULT_DOSStub_6021 {
  strings:
    $key_6021 = { 34 49 [2] 40 51 [2] 07 53 [2] 40 42 [2] 0e 4e [2] 02 44 [2] 15 4f [2] 0e 01 [2] 33 }

  condition:
    any of them
}