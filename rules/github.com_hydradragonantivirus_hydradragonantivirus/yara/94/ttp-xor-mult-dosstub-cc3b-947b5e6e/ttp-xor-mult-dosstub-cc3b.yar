rule TTP_XOR_MULT_DOSStub_cc3b {
  strings:
    $key_cc3b = { 98 53 [2] ec 4b [2] ab 49 [2] ec 58 [2] a2 54 [2] ae 5e [2] b9 55 [2] a2 1b [2] 9f }

  condition:
    any of them
}