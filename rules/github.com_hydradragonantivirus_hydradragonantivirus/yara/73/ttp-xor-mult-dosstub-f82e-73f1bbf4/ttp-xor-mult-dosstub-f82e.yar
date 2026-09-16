rule TTP_XOR_MULT_DOSStub_f82e {
  strings:
    $key_f82e = { ac 46 [2] d8 5e [2] 9f 5c [2] d8 4d [2] 96 41 [2] 9a 4b [2] 8d 40 [2] 96 0e [2] ab }

  condition:
    any of them
}