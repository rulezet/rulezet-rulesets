rule TTP_XOR_MULT_DOSStub_ba92 {
  strings:
    $key_ba92 = { ee fa [2] 9a e2 [2] dd e0 [2] 9a f1 [2] d4 fd [2] d8 f7 [2] cf fc [2] d4 b2 [2] e9 }

  condition:
    any of them
}