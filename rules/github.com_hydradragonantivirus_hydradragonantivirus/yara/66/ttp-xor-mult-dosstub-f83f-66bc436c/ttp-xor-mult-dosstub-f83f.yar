rule TTP_XOR_MULT_DOSStub_f83f {
  strings:
    $key_f83f = { ac 57 [2] d8 4f [2] 9f 4d [2] d8 5c [2] 96 50 [2] 9a 5a [2] 8d 51 [2] 96 1f [2] ab }

  condition:
    any of them
}