rule TTP_XOR_MULT_DOSStub_cc97 {
  strings:
    $key_cc97 = { 98 ff [2] ec e7 [2] ab e5 [2] ec f4 [2] a2 f8 [2] ae f2 [2] b9 f9 [2] a2 b7 [2] 9f }

  condition:
    any of them
}