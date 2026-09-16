rule TTP_XOR_MULT_DOSStub_d29d {
  strings:
    $key_d29d = { 86 f5 [2] f2 ed [2] b5 ef [2] f2 fe [2] bc f2 [2] b0 f8 [2] a7 f3 [2] bc bd [2] 81 }

  condition:
    any of them
}