rule TTP_XOR_MULT_DOSStub_f890 {
  strings:
    $key_f890 = { ac f8 [2] d8 e0 [2] 9f e2 [2] d8 f3 [2] 96 ff [2] 9a f5 [2] 8d fe [2] 96 b0 [2] ab }

  condition:
    any of them
}