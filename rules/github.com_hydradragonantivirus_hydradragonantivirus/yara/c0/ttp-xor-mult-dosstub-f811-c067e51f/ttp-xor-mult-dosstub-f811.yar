rule TTP_XOR_MULT_DOSStub_f811 {
  strings:
    $key_f811 = { ac 79 [2] d8 61 [2] 9f 63 [2] d8 72 [2] 96 7e [2] 9a 74 [2] 8d 7f [2] 96 31 [2] ab }

  condition:
    any of them
}