rule TTP_XOR_MULT_DOSStub_ee57 {
  strings:
    $key_ee57 = { ba 3f [2] ce 27 [2] 89 25 [2] ce 34 [2] 80 38 [2] 8c 32 [2] 9b 39 [2] 80 77 [2] bd }

  condition:
    any of them
}