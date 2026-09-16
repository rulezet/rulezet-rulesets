rule TTP_XOR_MULT_DOSStub_cc20 {
  strings:
    $key_cc20 = { 98 48 [2] ec 50 [2] ab 52 [2] ec 43 [2] a2 4f [2] ae 45 [2] b9 4e [2] a2 00 [2] 9f }

  condition:
    any of them
}