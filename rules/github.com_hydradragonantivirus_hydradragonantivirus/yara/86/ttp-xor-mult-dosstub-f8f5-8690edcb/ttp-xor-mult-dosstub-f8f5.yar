rule TTP_XOR_MULT_DOSStub_f8f5 {
  strings:
    $key_f8f5 = { ac 9d [2] d8 85 [2] 9f 87 [2] d8 96 [2] 96 9a [2] 9a 90 [2] 8d 9b [2] 96 d5 [2] ab }

  condition:
    any of them
}