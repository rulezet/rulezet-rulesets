rule TTP_XOR_MULT_DOSStub_7227 {
  strings:
    $key_7227 = { 26 4f [2] 52 57 [2] 15 55 [2] 52 44 [2] 1c 48 [2] 10 42 [2] 07 49 [2] 1c 07 [2] 21 }

  condition:
    any of them
}