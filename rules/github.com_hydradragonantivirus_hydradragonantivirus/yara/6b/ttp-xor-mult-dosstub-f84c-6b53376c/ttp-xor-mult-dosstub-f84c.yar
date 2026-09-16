rule TTP_XOR_MULT_DOSStub_f84c {
  strings:
    $key_f84c = { ac 24 [2] d8 3c [2] 9f 3e [2] d8 2f [2] 96 23 [2] 9a 29 [2] 8d 22 [2] 96 6c [2] ab }

  condition:
    any of them
}