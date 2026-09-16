rule TTP_XOR_MULT_DOSStub_c60e {
  strings:
    $key_c60e = { 92 66 [2] e6 7e [2] a1 7c [2] e6 6d [2] a8 61 [2] a4 6b [2] b3 60 [2] a8 2e [2] 95 }

  condition:
    any of them
}