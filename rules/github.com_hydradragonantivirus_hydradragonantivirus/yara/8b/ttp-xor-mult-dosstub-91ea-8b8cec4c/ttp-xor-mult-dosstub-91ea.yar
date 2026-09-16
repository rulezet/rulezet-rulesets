rule TTP_XOR_MULT_DOSStub_91ea {
  strings:
    $key_91ea = { c5 82 [2] b1 9a [2] f6 98 [2] b1 89 [2] ff 85 [2] f3 8f [2] e4 84 [2] ff ca [2] c2 }

  condition:
    any of them
}