rule TTP_XOR_MULT_DOSStub_c16e {
  strings:
    $key_c16e = { 95 06 [2] e1 1e [2] a6 1c [2] e1 0d [2] af 01 [2] a3 0b [2] b4 00 [2] af 4e [2] 92 }

  condition:
    any of them
}