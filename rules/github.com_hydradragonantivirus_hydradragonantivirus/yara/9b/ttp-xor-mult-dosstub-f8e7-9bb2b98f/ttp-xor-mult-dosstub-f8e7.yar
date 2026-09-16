rule TTP_XOR_MULT_DOSStub_f8e7 {
  strings:
    $key_f8e7 = { ac 8f [2] d8 97 [2] 9f 95 [2] d8 84 [2] 96 88 [2] 9a 82 [2] 8d 89 [2] 96 c7 [2] ab }

  condition:
    any of them
}