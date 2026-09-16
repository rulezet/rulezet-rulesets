rule TTP_XOR_MULT_DOSStub_f868 {
  strings:
    $key_f868 = { ac 00 [2] d8 18 [2] 9f 1a [2] d8 0b [2] 96 07 [2] 9a 0d [2] 8d 06 [2] 96 48 [2] ab }

  condition:
    any of them
}