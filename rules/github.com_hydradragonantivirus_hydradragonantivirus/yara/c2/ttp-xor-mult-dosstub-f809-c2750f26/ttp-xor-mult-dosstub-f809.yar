rule TTP_XOR_MULT_DOSStub_f809 {
  strings:
    $key_f809 = { ac 61 [2] d8 79 [2] 9f 7b [2] d8 6a [2] 96 66 [2] 9a 6c [2] 8d 67 [2] 96 29 [2] ab }

  condition:
    any of them
}