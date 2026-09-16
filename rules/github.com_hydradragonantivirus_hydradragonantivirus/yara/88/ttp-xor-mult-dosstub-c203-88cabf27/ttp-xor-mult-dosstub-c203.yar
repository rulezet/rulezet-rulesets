rule TTP_XOR_MULT_DOSStub_c203 {
  strings:
    $key_c203 = { 96 6b [2] e2 73 [2] a5 71 [2] e2 60 [2] ac 6c [2] a0 66 [2] b7 6d [2] ac 23 [2] 91 }

  condition:
    any of them
}