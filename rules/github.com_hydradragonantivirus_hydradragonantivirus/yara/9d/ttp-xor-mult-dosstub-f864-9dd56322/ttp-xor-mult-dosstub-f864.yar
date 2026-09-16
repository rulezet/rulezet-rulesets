rule TTP_XOR_MULT_DOSStub_f864 {
  strings:
    $key_f864 = { ac 0c [2] d8 14 [2] 9f 16 [2] d8 07 [2] 96 0b [2] 9a 01 [2] 8d 0a [2] 96 44 [2] ab }

  condition:
    any of them
}