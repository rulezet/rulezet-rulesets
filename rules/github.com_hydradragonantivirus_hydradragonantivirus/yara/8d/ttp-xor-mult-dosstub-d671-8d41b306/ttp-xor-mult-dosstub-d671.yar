rule TTP_XOR_MULT_DOSStub_d671 {
  strings:
    $key_d671 = { 82 19 [2] f6 01 [2] b1 03 [2] f6 12 [2] b8 1e [2] b4 14 [2] a3 1f [2] b8 51 [2] 85 }

  condition:
    any of them
}