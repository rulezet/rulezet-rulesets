rule TTP_XOR_MULT_DOSStub_ca0c {
  strings:
    $key_ca0c = { 9e 64 [2] ea 7c [2] ad 7e [2] ea 6f [2] a4 63 [2] a8 69 [2] bf 62 [2] a4 2c [2] 99 }

  condition:
    any of them
}