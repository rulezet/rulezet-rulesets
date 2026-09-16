rule TTP_XOR_MULT_DOSStub_d11d {
  strings:
    $key_d11d = { 85 75 [2] f1 6d [2] b6 6f [2] f1 7e [2] bf 72 [2] b3 78 [2] a4 73 [2] bf 3d [2] 82 }

  condition:
    any of them
}