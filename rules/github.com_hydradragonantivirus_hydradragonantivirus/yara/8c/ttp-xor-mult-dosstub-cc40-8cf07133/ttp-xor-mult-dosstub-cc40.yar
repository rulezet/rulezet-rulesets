rule TTP_XOR_MULT_DOSStub_cc40 {
  strings:
    $key_cc40 = { 98 28 [2] ec 30 [2] ab 32 [2] ec 23 [2] a2 2f [2] ae 25 [2] b9 2e [2] a2 60 [2] 9f }

  condition:
    any of them
}