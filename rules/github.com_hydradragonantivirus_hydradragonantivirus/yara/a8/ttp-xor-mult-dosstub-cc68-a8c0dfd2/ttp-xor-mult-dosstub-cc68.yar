rule TTP_XOR_MULT_DOSStub_cc68 {
  strings:
    $key_cc68 = { 98 00 [2] ec 18 [2] ab 1a [2] ec 0b [2] a2 07 [2] ae 0d [2] b9 06 [2] a2 48 [2] 9f }

  condition:
    any of them
}