rule TTP_XOR_MULT_DOSStub_7fa2 {
  strings:
    $key_7fa2 = { 2b ca [2] 5f d2 [2] 18 d0 [2] 5f c1 [2] 11 cd [2] 1d c7 [2] 0a cc [2] 11 82 [2] 2c }

  condition:
    any of them
}