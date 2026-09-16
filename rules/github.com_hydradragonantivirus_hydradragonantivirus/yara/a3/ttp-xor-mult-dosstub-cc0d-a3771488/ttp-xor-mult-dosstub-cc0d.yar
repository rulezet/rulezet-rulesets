rule TTP_XOR_MULT_DOSStub_cc0d {
  strings:
    $key_cc0d = { 98 65 [2] ec 7d [2] ab 7f [2] ec 6e [2] a2 62 [2] ae 68 [2] b9 63 [2] a2 2d [2] 9f }

  condition:
    any of them
}