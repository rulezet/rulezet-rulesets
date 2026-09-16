rule TTP_XOR_MULT_DOSStub_f806 {
  strings:
    $key_f806 = { ac 6e [2] d8 76 [2] 9f 74 [2] d8 65 [2] 96 69 [2] 9a 63 [2] 8d 68 [2] 96 26 [2] ab }

  condition:
    any of them
}