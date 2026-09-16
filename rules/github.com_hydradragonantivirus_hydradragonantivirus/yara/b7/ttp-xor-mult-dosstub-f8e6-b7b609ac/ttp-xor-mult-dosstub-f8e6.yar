rule TTP_XOR_MULT_DOSStub_f8e6 {
  strings:
    $key_f8e6 = { ac 8e [2] d8 96 [2] 9f 94 [2] d8 85 [2] 96 89 [2] 9a 83 [2] 8d 88 [2] 96 c6 [2] ab }

  condition:
    any of them
}