rule TTP_XOR_MULT_DOSStub_ee36 {
  strings:
    $key_ee36 = { ba 5e [2] ce 46 [2] 89 44 [2] ce 55 [2] 80 59 [2] 8c 53 [2] 9b 58 [2] 80 16 [2] bd }

  condition:
    any of them
}