rule TTP_XOR_MULT_DOSStub_f85a {
  strings:
    $key_f85a = { ac 32 [2] d8 2a [2] 9f 28 [2] d8 39 [2] 96 35 [2] 9a 3f [2] 8d 34 [2] 96 7a [2] ab }

  condition:
    any of them
}