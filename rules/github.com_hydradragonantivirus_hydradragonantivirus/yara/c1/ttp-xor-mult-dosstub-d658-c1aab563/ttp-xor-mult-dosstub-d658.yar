rule TTP_XOR_MULT_DOSStub_d658 {
  strings:
    $key_d658 = { 82 30 [2] f6 28 [2] b1 2a [2] f6 3b [2] b8 37 [2] b4 3d [2] a3 36 [2] b8 78 [2] 85 }

  condition:
    any of them
}