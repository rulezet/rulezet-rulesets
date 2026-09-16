rule TTP_XOR_MULT_DOSStub_f815 {
  strings:
    $key_f815 = { ac 7d [2] d8 65 [2] 9f 67 [2] d8 76 [2] 96 7a [2] 9a 70 [2] 8d 7b [2] 96 35 [2] ab }

  condition:
    any of them
}