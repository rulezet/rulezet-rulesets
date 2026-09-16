rule TTP_XOR_MULT_DOSStub_f834 {
  strings:
    $key_f834 = { ac 5c [2] d8 44 [2] 9f 46 [2] d8 57 [2] 96 5b [2] 9a 51 [2] 8d 5a [2] 96 14 [2] ab }

  condition:
    any of them
}