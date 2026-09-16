rule TTP_XOR_MULT_DOSStub_f84a {
  strings:
    $key_f84a = { ac 22 [2] d8 3a [2] 9f 38 [2] d8 29 [2] 96 25 [2] 9a 2f [2] 8d 24 [2] 96 6a [2] ab }

  condition:
    any of them
}