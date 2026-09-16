rule TTP_XOR_MULT_DOSStub_5227 {
  strings:
    $key_5227 = { 06 4f [2] 72 57 [2] 35 55 [2] 72 44 [2] 3c 48 [2] 30 42 [2] 27 49 [2] 3c 07 [2] 01 }

  condition:
    any of them
}