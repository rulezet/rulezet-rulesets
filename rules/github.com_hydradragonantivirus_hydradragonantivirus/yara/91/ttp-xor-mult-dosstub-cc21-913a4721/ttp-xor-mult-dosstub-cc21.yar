rule TTP_XOR_MULT_DOSStub_cc21 {
  strings:
    $key_cc21 = { 98 49 [2] ec 51 [2] ab 53 [2] ec 42 [2] a2 4e [2] ae 44 [2] b9 4f [2] a2 01 [2] 9f }

  condition:
    any of them
}