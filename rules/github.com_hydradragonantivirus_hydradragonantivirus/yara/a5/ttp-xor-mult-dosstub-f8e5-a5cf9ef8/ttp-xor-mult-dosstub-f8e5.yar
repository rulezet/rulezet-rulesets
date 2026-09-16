rule TTP_XOR_MULT_DOSStub_f8e5 {
  strings:
    $key_f8e5 = { ac 8d [2] d8 95 [2] 9f 97 [2] d8 86 [2] 96 8a [2] 9a 80 [2] 8d 8b [2] 96 c5 [2] ab }

  condition:
    any of them
}