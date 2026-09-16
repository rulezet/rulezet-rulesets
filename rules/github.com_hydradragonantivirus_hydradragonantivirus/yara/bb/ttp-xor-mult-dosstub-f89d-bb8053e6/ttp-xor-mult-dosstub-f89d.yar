rule TTP_XOR_MULT_DOSStub_f89d {
  strings:
    $key_f89d = { ac f5 [2] d8 ed [2] 9f ef [2] d8 fe [2] 96 f2 [2] 9a f8 [2] 8d f3 [2] 96 bd [2] ab }

  condition:
    any of them
}