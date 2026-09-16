rule TTP_XOR_MULT_DOSStub_cc2e {
  strings:
    $key_cc2e = { 98 46 [2] ec 5e [2] ab 5c [2] ec 4d [2] a2 41 [2] ae 4b [2] b9 40 [2] a2 0e [2] 9f }

  condition:
    any of them
}