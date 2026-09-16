rule TTP_XOR_MULT_DOSStub_cc4c {
  strings:
    $key_cc4c = { 98 24 [2] ec 3c [2] ab 3e [2] ec 2f [2] a2 23 [2] ae 29 [2] b9 22 [2] a2 6c [2] 9f }

  condition:
    any of them
}