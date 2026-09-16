rule TTP_XOR_MULT_DOSStub_f81a {
  strings:
    $key_f81a = { ac 72 [2] d8 6a [2] 9f 68 [2] d8 79 [2] 96 75 [2] 9a 7f [2] 8d 74 [2] 96 3a [2] ab }

  condition:
    any of them
}