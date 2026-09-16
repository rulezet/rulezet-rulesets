rule TTP_XOR_MULT_DOSStub_cc50 {
  strings:
    $key_cc50 = { 98 38 [2] ec 20 [2] ab 22 [2] ec 33 [2] a2 3f [2] ae 35 [2] b9 3e [2] a2 70 [2] 9f }

  condition:
    any of them
}