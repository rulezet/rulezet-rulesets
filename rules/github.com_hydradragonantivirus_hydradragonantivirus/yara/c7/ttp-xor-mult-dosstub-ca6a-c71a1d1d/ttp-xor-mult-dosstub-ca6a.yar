rule TTP_XOR_MULT_DOSStub_ca6a {
  strings:
    $key_ca6a = { 9e 02 [2] ea 1a [2] ad 18 [2] ea 09 [2] a4 05 [2] a8 0f [2] bf 04 [2] a4 4a [2] 99 }

  condition:
    any of them
}