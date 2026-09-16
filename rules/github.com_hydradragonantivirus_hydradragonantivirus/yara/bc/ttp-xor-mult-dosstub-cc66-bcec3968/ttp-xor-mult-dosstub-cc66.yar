rule TTP_XOR_MULT_DOSStub_cc66 {
  strings:
    $key_cc66 = { 98 0e [2] ec 16 [2] ab 14 [2] ec 05 [2] a2 09 [2] ae 03 [2] b9 08 [2] a2 46 [2] 9f }

  condition:
    any of them
}