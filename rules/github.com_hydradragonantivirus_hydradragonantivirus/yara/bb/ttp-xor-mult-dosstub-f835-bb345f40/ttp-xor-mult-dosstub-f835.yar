rule TTP_XOR_MULT_DOSStub_f835 {
  strings:
    $key_f835 = { ac 5d [2] d8 45 [2] 9f 47 [2] d8 56 [2] 96 5a [2] 9a 50 [2] 8d 5b [2] 96 15 [2] ab }

  condition:
    any of them
}