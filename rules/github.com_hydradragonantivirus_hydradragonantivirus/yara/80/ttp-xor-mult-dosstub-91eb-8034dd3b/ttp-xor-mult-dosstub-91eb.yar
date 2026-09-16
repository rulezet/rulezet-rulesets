rule TTP_XOR_MULT_DOSStub_91eb {
  strings:
    $key_91eb = { c5 83 [2] b1 9b [2] f6 99 [2] b1 88 [2] ff 84 [2] f3 8e [2] e4 85 [2] ff cb [2] c2 }

  condition:
    any of them
}