rule TTP_XOR_MULT_DOSStub_f802 {
  strings:
    $key_f802 = { ac 6a [2] d8 72 [2] 9f 70 [2] d8 61 [2] 96 6d [2] 9a 67 [2] 8d 6c [2] 96 22 [2] ab }

  condition:
    any of them
}