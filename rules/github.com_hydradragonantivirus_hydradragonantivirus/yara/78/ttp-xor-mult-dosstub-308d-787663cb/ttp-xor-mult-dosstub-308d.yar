rule TTP_XOR_MULT_DOSStub_308d {
  strings:
    $key_308d = { 64 e5 [2] 10 fd [2] 57 ff [2] 10 ee [2] 5e e2 [2] 52 e8 [2] 45 e3 [2] 5e ad [2] 63 }

  condition:
    any of them
}