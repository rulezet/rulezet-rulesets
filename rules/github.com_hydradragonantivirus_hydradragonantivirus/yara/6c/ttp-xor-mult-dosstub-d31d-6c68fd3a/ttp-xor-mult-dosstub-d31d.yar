rule TTP_XOR_MULT_DOSStub_d31d {
  strings:
    $key_d31d = { 87 75 [2] f3 6d [2] b4 6f [2] f3 7e [2] bd 72 [2] b1 78 [2] a6 73 [2] bd 3d [2] 80 }

  condition:
    any of them
}