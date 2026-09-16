rule TTP_XOR_MULT_DOSStub_cc7d {
  strings:
    $key_cc7d = { 98 15 [2] ec 0d [2] ab 0f [2] ec 1e [2] a2 12 [2] ae 18 [2] b9 13 [2] a2 5d [2] 9f }

  condition:
    any of them
}