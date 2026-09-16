rule TTP_XOR_MULT_DOSStub_f87a {
  strings:
    $key_f87a = { ac 12 [2] d8 0a [2] 9f 08 [2] d8 19 [2] 96 15 [2] 9a 1f [2] 8d 14 [2] 96 5a [2] ab }

  condition:
    any of them
}