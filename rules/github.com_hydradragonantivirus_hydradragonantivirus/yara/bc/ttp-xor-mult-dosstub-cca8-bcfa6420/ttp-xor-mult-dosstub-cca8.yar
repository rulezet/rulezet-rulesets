rule TTP_XOR_MULT_DOSStub_cca8 {
  strings:
    $key_cca8 = { 98 c0 [2] ec d8 [2] ab da [2] ec cb [2] a2 c7 [2] ae cd [2] b9 c6 [2] a2 88 [2] 9f }

  condition:
    any of them
}