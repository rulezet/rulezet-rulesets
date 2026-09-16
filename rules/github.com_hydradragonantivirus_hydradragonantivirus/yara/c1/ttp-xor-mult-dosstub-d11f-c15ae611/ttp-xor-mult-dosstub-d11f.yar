rule TTP_XOR_MULT_DOSStub_d11f {
  strings:
    $key_d11f = { 85 77 [2] f1 6f [2] b6 6d [2] f1 7c [2] bf 70 [2] b3 7a [2] a4 71 [2] bf 3f [2] 82 }

  condition:
    any of them
}