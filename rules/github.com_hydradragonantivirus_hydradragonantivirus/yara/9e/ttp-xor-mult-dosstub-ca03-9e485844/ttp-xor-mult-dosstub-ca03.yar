rule TTP_XOR_MULT_DOSStub_ca03 {
  strings:
    $key_ca03 = { 9e 6b [2] ea 73 [2] ad 71 [2] ea 60 [2] a4 6c [2] a8 66 [2] bf 6d [2] a4 23 [2] 99 }

  condition:
    any of them
}