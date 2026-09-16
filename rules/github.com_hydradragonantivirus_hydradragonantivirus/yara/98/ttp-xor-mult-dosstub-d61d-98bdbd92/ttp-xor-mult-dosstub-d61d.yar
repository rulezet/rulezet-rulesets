rule TTP_XOR_MULT_DOSStub_d61d {
  strings:
    $key_d61d = { 82 75 [2] f6 6d [2] b1 6f [2] f6 7e [2] b8 72 [2] b4 78 [2] a3 73 [2] b8 3d [2] 85 }

  condition:
    any of them
}