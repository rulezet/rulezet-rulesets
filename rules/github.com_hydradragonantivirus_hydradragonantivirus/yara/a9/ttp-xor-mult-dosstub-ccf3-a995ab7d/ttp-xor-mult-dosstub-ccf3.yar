rule TTP_XOR_MULT_DOSStub_ccf3 {
  strings:
    $key_ccf3 = { 98 9b [2] ec 83 [2] ab 81 [2] ec 90 [2] a2 9c [2] ae 96 [2] b9 9d [2] a2 d3 [2] 9f }

  condition:
    any of them
}