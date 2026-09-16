rule TTP_XOR_MULT_DOSStub_c11e {
  strings:
    $key_c11e = { 95 76 [2] e1 6e [2] a6 6c [2] e1 7d [2] af 71 [2] a3 7b [2] b4 70 [2] af 3e [2] 92 }

  condition:
    any of them
}