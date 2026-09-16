rule TTP_XOR_MULT_DOSStub_ccfb {
  strings:
    $key_ccfb = { 98 93 [2] ec 8b [2] ab 89 [2] ec 98 [2] a2 94 [2] ae 9e [2] b9 95 [2] a2 db [2] 9f }

  condition:
    any of them
}