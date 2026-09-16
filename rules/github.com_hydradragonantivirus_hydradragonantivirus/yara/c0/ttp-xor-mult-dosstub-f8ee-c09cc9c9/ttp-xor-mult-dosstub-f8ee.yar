rule TTP_XOR_MULT_DOSStub_f8ee {
  strings:
    $key_f8ee = { ac 86 [2] d8 9e [2] 9f 9c [2] d8 8d [2] 96 81 [2] 9a 8b [2] 8d 80 [2] 96 ce [2] ab }

  condition:
    any of them
}