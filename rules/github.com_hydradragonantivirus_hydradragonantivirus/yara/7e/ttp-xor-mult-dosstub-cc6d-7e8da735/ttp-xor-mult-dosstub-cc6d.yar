rule TTP_XOR_MULT_DOSStub_cc6d {
  strings:
    $key_cc6d = { 98 05 [2] ec 1d [2] ab 1f [2] ec 0e [2] a2 02 [2] ae 08 [2] b9 03 [2] a2 4d [2] 9f }

  condition:
    any of them
}