rule TTP_XOR_MULT_DOSStub_f840 {
  strings:
    $key_f840 = { ac 28 [2] d8 30 [2] 9f 32 [2] d8 23 [2] 96 2f [2] 9a 25 [2] 8d 2e [2] 96 60 [2] ab }

  condition:
    any of them
}