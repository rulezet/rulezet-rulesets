rule TTP_XOR_MULT_DOSStub_cc5e {
  strings:
    $key_cc5e = { 98 36 [2] ec 2e [2] ab 2c [2] ec 3d [2] a2 31 [2] ae 3b [2] b9 30 [2] a2 7e [2] 9f }

  condition:
    any of them
}