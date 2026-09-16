rule TTP_XOR_MULT_DOSStub_f8a8 {
  strings:
    $key_f8a8 = { ac c0 [2] d8 d8 [2] 9f da [2] d8 cb [2] 96 c7 [2] 9a cd [2] 8d c6 [2] 96 88 [2] ab }

  condition:
    any of them
}