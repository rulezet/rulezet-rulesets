rule TTP_XOR_MULT_DOSStub_eecb {
  strings:
    $key_eecb = { ba a3 [2] ce bb [2] 89 b9 [2] ce a8 [2] 80 a4 [2] 8c ae [2] 9b a5 [2] 80 eb [2] bd }

  condition:
    any of them
}