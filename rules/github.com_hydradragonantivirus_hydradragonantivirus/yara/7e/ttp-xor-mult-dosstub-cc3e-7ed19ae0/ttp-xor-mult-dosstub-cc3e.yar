rule TTP_XOR_MULT_DOSStub_cc3e {
  strings:
    $key_cc3e = { 98 56 [2] ec 4e [2] ab 4c [2] ec 5d [2] a2 51 [2] ae 5b [2] b9 50 [2] a2 1e [2] 9f }

  condition:
    any of them
}