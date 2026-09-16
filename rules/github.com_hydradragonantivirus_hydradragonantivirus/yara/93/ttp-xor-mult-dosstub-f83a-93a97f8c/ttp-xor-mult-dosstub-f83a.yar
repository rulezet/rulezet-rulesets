rule TTP_XOR_MULT_DOSStub_f83a {
  strings:
    $key_f83a = { ac 52 [2] d8 4a [2] 9f 48 [2] d8 59 [2] 96 55 [2] 9a 5f [2] 8d 54 [2] 96 1a [2] ab }

  condition:
    any of them
}