rule TTP_XOR_MULT_DOSStub_f865 {
  strings:
    $key_f865 = { ac 0d [2] d8 15 [2] 9f 17 [2] d8 06 [2] 96 0a [2] 9a 00 [2] 8d 0b [2] 96 45 [2] ab }

  condition:
    any of them
}