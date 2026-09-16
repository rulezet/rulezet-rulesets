rule TTP_XOR_MULT_DOSStub_f817 {
  strings:
    $key_f817 = { ac 7f [2] d8 67 [2] 9f 65 [2] d8 74 [2] 96 78 [2] 9a 72 [2] 8d 79 [2] 96 37 [2] ab }

  condition:
    any of them
}