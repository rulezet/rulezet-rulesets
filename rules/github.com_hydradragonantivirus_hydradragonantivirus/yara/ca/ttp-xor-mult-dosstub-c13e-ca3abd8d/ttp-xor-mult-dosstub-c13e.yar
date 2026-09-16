rule TTP_XOR_MULT_DOSStub_c13e {
  strings:
    $key_c13e = { 95 56 [2] e1 4e [2] a6 4c [2] e1 5d [2] af 51 [2] a3 5b [2] b4 50 [2] af 1e [2] 92 }

  condition:
    any of them
}