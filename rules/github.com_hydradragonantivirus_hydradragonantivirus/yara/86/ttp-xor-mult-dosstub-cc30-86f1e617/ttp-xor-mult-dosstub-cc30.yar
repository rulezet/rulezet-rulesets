rule TTP_XOR_MULT_DOSStub_cc30 {
  strings:
    $key_cc30 = { 98 58 [2] ec 40 [2] ab 42 [2] ec 53 [2] a2 5f [2] ae 55 [2] b9 5e [2] a2 10 [2] 9f }

  condition:
    any of them
}