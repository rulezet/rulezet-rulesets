rule TTP_XOR_MULT_DOSStub_cc02 {
  strings:
    $key_cc02 = { 98 6a [2] ec 72 [2] ab 70 [2] ec 61 [2] a2 6d [2] ae 67 [2] b9 6c [2] a2 22 [2] 9f }

  condition:
    any of them
}