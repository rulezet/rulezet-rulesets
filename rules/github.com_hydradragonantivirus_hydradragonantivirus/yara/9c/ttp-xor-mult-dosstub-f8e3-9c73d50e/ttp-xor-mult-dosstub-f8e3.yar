rule TTP_XOR_MULT_DOSStub_f8e3 {
  strings:
    $key_f8e3 = { ac 8b [2] d8 93 [2] 9f 91 [2] d8 80 [2] 96 8c [2] 9a 86 [2] 8d 8d [2] 96 c3 [2] ab }

  condition:
    any of them
}