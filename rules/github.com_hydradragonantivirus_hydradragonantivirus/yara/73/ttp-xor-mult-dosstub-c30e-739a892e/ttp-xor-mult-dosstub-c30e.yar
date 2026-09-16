rule TTP_XOR_MULT_DOSStub_c30e {
  strings:
    $key_c30e = { 97 66 [2] e3 7e [2] a4 7c [2] e3 6d [2] ad 61 [2] a1 6b [2] b6 60 [2] ad 2e [2] 90 }

  condition:
    any of them
}