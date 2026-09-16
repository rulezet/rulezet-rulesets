rule TTP_XOR_MULT_DOSStub_f819 {
  strings:
    $key_f819 = { ac 71 [2] d8 69 [2] 9f 6b [2] d8 7a [2] 96 76 [2] 9a 7c [2] 8d 77 [2] 96 39 [2] ab }

  condition:
    any of them
}