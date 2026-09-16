rule TTP_XOR_MULT_DOSStub_f848 {
  strings:
    $key_f848 = { ac 20 [2] d8 38 [2] 9f 3a [2] d8 2b [2] 96 27 [2] 9a 2d [2] 8d 26 [2] 96 68 [2] ab }

  condition:
    any of them
}