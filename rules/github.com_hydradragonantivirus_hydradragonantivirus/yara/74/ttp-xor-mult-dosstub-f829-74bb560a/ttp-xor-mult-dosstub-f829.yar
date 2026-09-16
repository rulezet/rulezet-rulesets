rule TTP_XOR_MULT_DOSStub_f829 {
  strings:
    $key_f829 = { ac 41 [2] d8 59 [2] 9f 5b [2] d8 4a [2] 96 46 [2] 9a 4c [2] 8d 47 [2] 96 09 [2] ab }

  condition:
    any of them
}