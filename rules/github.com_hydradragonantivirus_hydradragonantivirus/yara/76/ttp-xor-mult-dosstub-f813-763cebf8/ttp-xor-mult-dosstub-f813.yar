rule TTP_XOR_MULT_DOSStub_f813 {
  strings:
    $key_f813 = { ac 7b [2] d8 63 [2] 9f 61 [2] d8 70 [2] 96 7c [2] 9a 76 [2] 8d 7d [2] 96 33 [2] ab }

  condition:
    any of them
}