rule TTP_XOR_MULT_DOSStub_efa2 {
  strings:
    $key_efa2 = { bb ca [2] cf d2 [2] 88 d0 [2] cf c1 [2] 81 cd [2] 8d c7 [2] 9a cc [2] 81 82 [2] bc }

  condition:
    any of them
}