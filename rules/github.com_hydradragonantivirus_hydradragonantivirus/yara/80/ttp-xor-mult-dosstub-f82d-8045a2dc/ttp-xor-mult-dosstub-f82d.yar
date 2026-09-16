rule TTP_XOR_MULT_DOSStub_f82d {
  strings:
    $key_f82d = { ac 45 [2] d8 5d [2] 9f 5f [2] d8 4e [2] 96 42 [2] 9a 48 [2] 8d 43 [2] 96 0d [2] ab }

  condition:
    any of them
}