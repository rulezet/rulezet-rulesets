rule TTP_XOR_MULT_DOSStub_f808 {
  strings:
    $key_f808 = { ac 60 [2] d8 78 [2] 9f 7a [2] d8 6b [2] 96 67 [2] 9a 6d [2] 8d 66 [2] 96 28 [2] ab }

  condition:
    any of them
}