rule TTP_XOR_MULT_DOSStub_f8f6 {
  strings:
    $key_f8f6 = { ac 9e [2] d8 86 [2] 9f 84 [2] d8 95 [2] 96 99 [2] 9a 93 [2] 8d 98 [2] 96 d6 [2] ab }

  condition:
    any of them
}