rule TTP_XOR_MULT_DOSStub_cc5b {
  strings:
    $key_cc5b = { 98 33 [2] ec 2b [2] ab 29 [2] ec 38 [2] a2 34 [2] ae 3e [2] b9 35 [2] a2 7b [2] 9f }

  condition:
    any of them
}