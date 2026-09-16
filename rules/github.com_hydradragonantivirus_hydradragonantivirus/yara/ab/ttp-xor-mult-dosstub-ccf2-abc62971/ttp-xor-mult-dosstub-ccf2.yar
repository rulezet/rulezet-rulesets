rule TTP_XOR_MULT_DOSStub_ccf2 {
  strings:
    $key_ccf2 = { 98 9a [2] ec 82 [2] ab 80 [2] ec 91 [2] a2 9d [2] ae 97 [2] b9 9c [2] a2 d2 [2] 9f }

  condition:
    any of them
}