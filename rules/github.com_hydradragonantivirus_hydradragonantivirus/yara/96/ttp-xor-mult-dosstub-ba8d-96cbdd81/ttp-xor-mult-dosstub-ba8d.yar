rule TTP_XOR_MULT_DOSStub_ba8d {
  strings:
    $key_ba8d = { ee e5 [2] 9a fd [2] dd ff [2] 9a ee [2] d4 e2 [2] d8 e8 [2] cf e3 [2] d4 ad [2] e9 }

  condition:
    any of them
}