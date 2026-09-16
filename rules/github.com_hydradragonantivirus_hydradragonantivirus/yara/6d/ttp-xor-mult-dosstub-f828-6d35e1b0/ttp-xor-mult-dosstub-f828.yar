rule TTP_XOR_MULT_DOSStub_f828 {
  strings:
    $key_f828 = { ac 40 [2] d8 58 [2] 9f 5a [2] d8 4b [2] 96 47 [2] 9a 4d [2] 8d 46 [2] 96 08 [2] ab }

  condition:
    any of them
}