rule TTP_XOR_MULT_DOSStub_33ce {
  strings:
    $key_33ce = { 67 a6 [2] 13 be [2] 54 bc [2] 13 ad [2] 5d a1 [2] 51 ab [2] 46 a0 [2] 5d ee [2] 60 }

  condition:
    any of them
}