rule TTP_XOR_MULT_DOSStub_cc17 {
  strings:
    $key_cc17 = { 98 7f [2] ec 67 [2] ab 65 [2] ec 74 [2] a2 78 [2] ae 72 [2] b9 79 [2] a2 37 [2] 9f }

  condition:
    any of them
}