rule TTP_XOR_MULT_DOSStub_eec6 {
  strings:
    $key_eec6 = { ba ae [2] ce b6 [2] 89 b4 [2] ce a5 [2] 80 a9 [2] 8c a3 [2] 9b a8 [2] 80 e6 [2] bd }

  condition:
    any of them
}