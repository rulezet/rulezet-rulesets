rule TTP_XOR_MULT_DOSStub_f85e {
  strings:
    $key_f85e = { ac 36 [2] d8 2e [2] 9f 2c [2] d8 3d [2] 96 31 [2] 9a 3b [2] 8d 30 [2] 96 7e [2] ab }

  condition:
    any of them
}