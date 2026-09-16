rule TTP_XOR_MULT_DOSStub_569c {
  strings:
    $key_569c = { 02 f4 [2] 76 ec [2] 31 ee [2] 76 ff [2] 38 f3 [2] 34 f9 [2] 23 f2 [2] 38 bc [2] 05 }

  condition:
    any of them
}