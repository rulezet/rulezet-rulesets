rule TTP_XOR_MULT_DOSStub_c10e {
  strings:
    $key_c10e = { 95 66 [2] e1 7e [2] a6 7c [2] e1 6d [2] af 61 [2] a3 6b [2] b4 60 [2] af 2e [2] 92 }

  condition:
    any of them
}