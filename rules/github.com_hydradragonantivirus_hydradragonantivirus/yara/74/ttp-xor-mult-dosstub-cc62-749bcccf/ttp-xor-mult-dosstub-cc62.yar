rule TTP_XOR_MULT_DOSStub_cc62 {
  strings:
    $key_cc62 = { 98 0a [2] ec 12 [2] ab 10 [2] ec 01 [2] a2 0d [2] ae 07 [2] b9 0c [2] a2 42 [2] 9f }

  condition:
    any of them
}