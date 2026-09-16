rule TTP_XOR_MULT_DOSStub_cc46 {
  strings:
    $key_cc46 = { 98 2e [2] ec 36 [2] ab 34 [2] ec 25 [2] a2 29 [2] ae 23 [2] b9 28 [2] a2 66 [2] 9f }

  condition:
    any of them
}