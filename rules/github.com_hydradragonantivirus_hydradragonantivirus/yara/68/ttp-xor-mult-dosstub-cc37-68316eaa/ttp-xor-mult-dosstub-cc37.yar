rule TTP_XOR_MULT_DOSStub_cc37 {
  strings:
    $key_cc37 = { 98 5f [2] ec 47 [2] ab 45 [2] ec 54 [2] a2 58 [2] ae 52 [2] b9 59 [2] a2 17 [2] 9f }

  condition:
    any of them
}