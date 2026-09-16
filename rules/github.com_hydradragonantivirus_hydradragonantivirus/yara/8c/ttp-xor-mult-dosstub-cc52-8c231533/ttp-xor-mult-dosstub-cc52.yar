rule TTP_XOR_MULT_DOSStub_cc52 {
  strings:
    $key_cc52 = { 98 3a [2] ec 22 [2] ab 20 [2] ec 31 [2] a2 3d [2] ae 37 [2] b9 3c [2] a2 72 [2] 9f }

  condition:
    any of them
}