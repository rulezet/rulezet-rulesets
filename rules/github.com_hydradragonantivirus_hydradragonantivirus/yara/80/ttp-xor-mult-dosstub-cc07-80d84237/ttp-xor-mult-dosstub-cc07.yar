rule TTP_XOR_MULT_DOSStub_cc07 {
  strings:
    $key_cc07 = { 98 6f [2] ec 77 [2] ab 75 [2] ec 64 [2] a2 68 [2] ae 62 [2] b9 69 [2] a2 27 [2] 9f }

  condition:
    any of them
}