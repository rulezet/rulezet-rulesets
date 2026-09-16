rule TTP_XOR_MULT_DOSStub_f824 {
  strings:
    $key_f824 = { ac 4c [2] d8 54 [2] 9f 56 [2] d8 47 [2] 96 4b [2] 9a 41 [2] 8d 4a [2] 96 04 [2] ab }

  condition:
    any of them
}