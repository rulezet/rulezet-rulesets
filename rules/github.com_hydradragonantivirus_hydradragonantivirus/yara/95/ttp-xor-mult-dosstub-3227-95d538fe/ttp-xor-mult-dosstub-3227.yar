rule TTP_XOR_MULT_DOSStub_3227 {
  strings:
    $key_3227 = { 66 4f [2] 12 57 [2] 55 55 [2] 12 44 [2] 5c 48 [2] 50 42 [2] 47 49 [2] 5c 07 [2] 61 }

  condition:
    any of them
}