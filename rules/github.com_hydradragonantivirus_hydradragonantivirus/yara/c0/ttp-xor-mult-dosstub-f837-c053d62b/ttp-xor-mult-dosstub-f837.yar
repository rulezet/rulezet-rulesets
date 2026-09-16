rule TTP_XOR_MULT_DOSStub_f837 {
  strings:
    $key_f837 = { ac 5f [2] d8 47 [2] 9f 45 [2] d8 54 [2] 96 58 [2] 9a 52 [2] 8d 59 [2] 96 17 [2] ab }

  condition:
    any of them
}