rule TTP_XOR_MULT_DOSStub_f8a5 {
  strings:
    $key_f8a5 = { ac cd [2] d8 d5 [2] 9f d7 [2] d8 c6 [2] 96 ca [2] 9a c0 [2] 8d cb [2] 96 85 [2] ab }

  condition:
    any of them
}