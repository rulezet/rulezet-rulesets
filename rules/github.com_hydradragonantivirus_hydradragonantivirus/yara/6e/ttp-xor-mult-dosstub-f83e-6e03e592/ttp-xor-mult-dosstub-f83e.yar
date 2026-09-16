rule TTP_XOR_MULT_DOSStub_f83e {
  strings:
    $key_f83e = { ac 56 [2] d8 4e [2] 9f 4c [2] d8 5d [2] 96 51 [2] 9a 5b [2] 8d 50 [2] 96 1e [2] ab }

  condition:
    any of them
}