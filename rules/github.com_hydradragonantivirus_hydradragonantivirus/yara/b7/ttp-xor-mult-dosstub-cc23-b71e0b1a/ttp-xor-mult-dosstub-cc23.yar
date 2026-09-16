rule TTP_XOR_MULT_DOSStub_cc23 {
  strings:
    $key_cc23 = { 98 4b [2] ec 53 [2] ab 51 [2] ec 40 [2] a2 4c [2] ae 46 [2] b9 4d [2] a2 03 [2] 9f }

  condition:
    any of them
}