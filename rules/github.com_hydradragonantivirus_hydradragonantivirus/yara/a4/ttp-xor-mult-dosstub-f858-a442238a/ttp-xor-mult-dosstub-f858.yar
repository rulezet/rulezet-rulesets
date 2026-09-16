rule TTP_XOR_MULT_DOSStub_f858 {
  strings:
    $key_f858 = { ac 30 [2] d8 28 [2] 9f 2a [2] d8 3b [2] 96 37 [2] 9a 3d [2] 8d 36 [2] 96 78 [2] ab }

  condition:
    any of them
}