rule TTP_XOR_MULT_DOSStub_6007 {
  strings:
    $key_6007 = { 34 6f [2] 40 77 [2] 07 75 [2] 40 64 [2] 0e 68 [2] 02 62 [2] 15 69 [2] 0e 27 [2] 33 }

  condition:
    any of them
}