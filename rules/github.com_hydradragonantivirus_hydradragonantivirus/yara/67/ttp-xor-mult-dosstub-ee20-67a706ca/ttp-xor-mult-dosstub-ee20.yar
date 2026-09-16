rule TTP_XOR_MULT_DOSStub_ee20 {
  strings:
    $key_ee20 = { ba 48 [2] ce 50 [2] 89 52 [2] ce 43 [2] 80 4f [2] 8c 45 [2] 9b 4e [2] 80 00 [2] bd }

  condition:
    any of them
}