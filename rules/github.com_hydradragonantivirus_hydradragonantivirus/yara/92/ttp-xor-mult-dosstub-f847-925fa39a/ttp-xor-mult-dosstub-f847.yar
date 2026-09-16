rule TTP_XOR_MULT_DOSStub_f847 {
  strings:
    $key_f847 = { ac 2f [2] d8 37 [2] 9f 35 [2] d8 24 [2] 96 28 [2] 9a 22 [2] 8d 29 [2] 96 67 [2] ab }

  condition:
    any of them
}