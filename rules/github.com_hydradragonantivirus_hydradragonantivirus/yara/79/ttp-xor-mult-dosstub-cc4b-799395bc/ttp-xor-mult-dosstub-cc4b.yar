rule TTP_XOR_MULT_DOSStub_cc4b {
  strings:
    $key_cc4b = { 98 23 [2] ec 3b [2] ab 39 [2] ec 28 [2] a2 24 [2] ae 2e [2] b9 25 [2] a2 6b [2] 9f }

  condition:
    any of them
}