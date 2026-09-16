rule TTP_XOR_MULT_DOSStub_cc51 {
  strings:
    $key_cc51 = { 98 39 [2] ec 21 [2] ab 23 [2] ec 32 [2] a2 3e [2] ae 34 [2] b9 3f [2] a2 71 [2] 9f }

  condition:
    any of them
}