rule TTP_XOR_MULT_DOSStub_228d {
  strings:
    $key_228d = { 76 e5 [2] 02 fd [2] 45 ff [2] 02 ee [2] 4c e2 [2] 40 e8 [2] 57 e3 [2] 4c ad [2] 71 }

  condition:
    any of them
}