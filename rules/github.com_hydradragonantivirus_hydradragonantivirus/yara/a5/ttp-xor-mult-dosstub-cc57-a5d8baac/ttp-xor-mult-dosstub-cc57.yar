rule TTP_XOR_MULT_DOSStub_cc57 {
  strings:
    $key_cc57 = { 98 3f [2] ec 27 [2] ab 25 [2] ec 34 [2] a2 38 [2] ae 32 [2] b9 39 [2] a2 77 [2] 9f }

  condition:
    any of them
}