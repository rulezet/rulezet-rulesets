rule TTP_XOR_MULT_DOSStub_ca6b {
  strings:
    $key_ca6b = { 9e 03 [2] ea 1b [2] ad 19 [2] ea 08 [2] a4 04 [2] a8 0e [2] bf 05 [2] a4 4b [2] 99 }

  condition:
    any of them
}