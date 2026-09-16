rule TTP_XOR_MULT_DOSStub_f8f4 {
  strings:
    $key_f8f4 = { ac 9c [2] d8 84 [2] 9f 86 [2] d8 97 [2] 96 9b [2] 9a 91 [2] 8d 9a [2] 96 d4 [2] ab }

  condition:
    any of them
}