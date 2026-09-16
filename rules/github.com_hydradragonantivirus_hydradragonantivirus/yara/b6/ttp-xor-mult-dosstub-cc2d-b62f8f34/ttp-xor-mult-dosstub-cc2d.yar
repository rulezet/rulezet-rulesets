rule TTP_XOR_MULT_DOSStub_cc2d {
  strings:
    $key_cc2d = { 98 45 [2] ec 5d [2] ab 5f [2] ec 4e [2] a2 42 [2] ae 48 [2] b9 43 [2] a2 0d [2] 9f }

  condition:
    any of them
}