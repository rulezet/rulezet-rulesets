rule TTP_XOR_MULT_DOSStub_f8fa {
  strings:
    $key_f8fa = { ac 92 [2] d8 8a [2] 9f 88 [2] d8 99 [2] 96 95 [2] 9a 9f [2] 8d 94 [2] 96 da [2] ab }

  condition:
    any of them
}