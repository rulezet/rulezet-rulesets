rule TTP_XOR_MULT_DOSStub_d11c {
  strings:
    $key_d11c = { 85 74 [2] f1 6c [2] b6 6e [2] f1 7f [2] bf 73 [2] b3 79 [2] a4 72 [2] bf 3c [2] 82 }

  condition:
    any of them
}