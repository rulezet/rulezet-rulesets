rule TTP_XOR_MULT_DOSStub_eec7 {
  strings:
    $key_eec7 = { ba af [2] ce b7 [2] 89 b5 [2] ce a4 [2] 80 a8 [2] 8c a2 [2] 9b a9 [2] 80 e7 [2] bd }

  condition:
    any of them
}