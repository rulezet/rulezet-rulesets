rule TTP_XOR_MULT_DOSStub_f814 {
  strings:
    $key_f814 = { ac 7c [2] d8 64 [2] 9f 66 [2] d8 77 [2] 96 7b [2] 9a 71 [2] 8d 7a [2] 96 34 [2] ab }

  condition:
    any of them
}