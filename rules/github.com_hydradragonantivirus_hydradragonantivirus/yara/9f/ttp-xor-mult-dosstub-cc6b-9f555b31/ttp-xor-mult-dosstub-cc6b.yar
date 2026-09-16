rule TTP_XOR_MULT_DOSStub_cc6b {
  strings:
    $key_cc6b = { 98 03 [2] ec 1b [2] ab 19 [2] ec 08 [2] a2 04 [2] ae 0e [2] b9 05 [2] a2 4b [2] 9f }

  condition:
    any of them
}