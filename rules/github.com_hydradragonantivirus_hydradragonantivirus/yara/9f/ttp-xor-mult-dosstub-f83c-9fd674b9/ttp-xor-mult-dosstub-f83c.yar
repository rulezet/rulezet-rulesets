rule TTP_XOR_MULT_DOSStub_f83c {
  strings:
    $key_f83c = { ac 54 [2] d8 4c [2] 9f 4e [2] d8 5f [2] 96 53 [2] 9a 59 [2] 8d 52 [2] 96 1c [2] ab }

  condition:
    any of them
}