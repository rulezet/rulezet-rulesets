rule TTP_XOR_MULT_DOSStub_cc70 {
  strings:
    $key_cc70 = { 98 18 [2] ec 00 [2] ab 02 [2] ec 13 [2] a2 1f [2] ae 15 [2] b9 1e [2] a2 50 [2] 9f }

  condition:
    any of them
}