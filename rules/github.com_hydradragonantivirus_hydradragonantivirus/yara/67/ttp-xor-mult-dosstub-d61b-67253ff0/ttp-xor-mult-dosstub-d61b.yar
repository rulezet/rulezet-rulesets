rule TTP_XOR_MULT_DOSStub_d61b {
  strings:
    $key_d61b = { 82 73 [2] f6 6b [2] b1 69 [2] f6 78 [2] b8 74 [2] b4 7e [2] a3 75 [2] b8 3b [2] 85 }

  condition:
    any of them
}