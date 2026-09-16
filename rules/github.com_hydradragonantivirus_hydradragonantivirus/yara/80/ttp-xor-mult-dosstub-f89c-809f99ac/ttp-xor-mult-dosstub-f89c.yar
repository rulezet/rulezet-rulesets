rule TTP_XOR_MULT_DOSStub_f89c {
  strings:
    $key_f89c = { ac f4 [2] d8 ec [2] 9f ee [2] d8 ff [2] 96 f3 [2] 9a f9 [2] 8d f2 [2] 96 bc [2] ab }

  condition:
    any of them
}