rule TTP_XOR_MULT_DOSStub_f8ce {
  strings:
    $key_f8ce = { ac a6 [2] d8 be [2] 9f bc [2] d8 ad [2] 96 a1 [2] 9a ab [2] 8d a0 [2] 96 ee [2] ab }

  condition:
    any of them
}