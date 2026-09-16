rule TTP_XOR_MULT_DOSStub_cc5c {
  strings:
    $key_cc5c = { 98 34 [2] ec 2c [2] ab 2e [2] ec 3f [2] a2 33 [2] ae 39 [2] b9 32 [2] a2 7c [2] 9f }

  condition:
    any of them
}