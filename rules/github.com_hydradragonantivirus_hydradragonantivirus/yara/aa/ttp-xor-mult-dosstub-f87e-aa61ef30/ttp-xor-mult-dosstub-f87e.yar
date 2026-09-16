rule TTP_XOR_MULT_DOSStub_f87e {
  strings:
    $key_f87e = { ac 16 [2] d8 0e [2] 9f 0c [2] d8 1d [2] 96 11 [2] 9a 1b [2] 8d 10 [2] 96 5e [2] ab }

  condition:
    any of them
}