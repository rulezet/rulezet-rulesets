rule TTP_XOR_MULT_DOSStub_ca04 {
  strings:
    $key_ca04 = { 9e 6c [2] ea 74 [2] ad 76 [2] ea 67 [2] a4 6b [2] a8 61 [2] bf 6a [2] a4 24 [2] 99 }

  condition:
    any of them
}