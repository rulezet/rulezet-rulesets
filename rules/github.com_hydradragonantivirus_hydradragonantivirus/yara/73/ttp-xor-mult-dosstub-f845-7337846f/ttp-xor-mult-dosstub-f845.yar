rule TTP_XOR_MULT_DOSStub_f845 {
  strings:
    $key_f845 = { ac 2d [2] d8 35 [2] 9f 37 [2] d8 26 [2] 96 2a [2] 9a 20 [2] 8d 2b [2] 96 65 [2] ab }

  condition:
    any of them
}