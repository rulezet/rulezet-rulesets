rule TTP_XOR_MULT_DOSStub_cc0e {
  strings:
    $key_cc0e = { 98 66 [2] ec 7e [2] ab 7c [2] ec 6d [2] a2 61 [2] ae 6b [2] b9 60 [2] a2 2e [2] 9f }

  condition:
    any of them
}