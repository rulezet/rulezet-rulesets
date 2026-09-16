rule TTP_XOR_MULT_DOSStub_388d {
  strings:
    $key_388d = { 6c e5 [2] 18 fd [2] 5f ff [2] 18 ee [2] 56 e2 [2] 5a e8 [2] 4d e3 [2] 56 ad [2] 6b }

  condition:
    any of them
}