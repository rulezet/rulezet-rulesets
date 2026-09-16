rule TTP_XOR_MULT_DOSStub_eec5 {
  strings:
    $key_eec5 = { ba ad [2] ce b5 [2] 89 b7 [2] ce a6 [2] 80 aa [2] 8c a0 [2] 9b ab [2] 80 e5 [2] bd }

  condition:
    any of them
}