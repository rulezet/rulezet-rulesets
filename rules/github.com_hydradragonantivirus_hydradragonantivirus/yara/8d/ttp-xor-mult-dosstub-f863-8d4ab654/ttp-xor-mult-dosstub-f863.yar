rule TTP_XOR_MULT_DOSStub_f863 {
  strings:
    $key_f863 = { ac 0b [2] d8 13 [2] 9f 11 [2] d8 00 [2] 96 0c [2] 9a 06 [2] 8d 0d [2] 96 43 [2] ab }

  condition:
    any of them
}