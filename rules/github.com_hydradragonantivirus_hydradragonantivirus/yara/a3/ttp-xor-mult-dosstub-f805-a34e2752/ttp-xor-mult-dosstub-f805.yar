rule TTP_XOR_MULT_DOSStub_f805 {
  strings:
    $key_f805 = { ac 6d [2] d8 75 [2] 9f 77 [2] d8 66 [2] 96 6a [2] 9a 60 [2] 8d 6b [2] 96 25 [2] ab }

  condition:
    any of them
}