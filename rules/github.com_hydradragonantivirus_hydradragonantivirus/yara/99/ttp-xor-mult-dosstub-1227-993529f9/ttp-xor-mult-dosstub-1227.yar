rule TTP_XOR_MULT_DOSStub_1227 {
  strings:
    $key_1227 = { 46 4f [2] 32 57 [2] 75 55 [2] 32 44 [2] 7c 48 [2] 70 42 [2] 67 49 [2] 7c 07 [2] 41 }

  condition:
    any of them
}