rule TTP_XOR_MULT_DOSStub_ee60 {
  strings:
    $key_ee60 = { ba 08 [2] ce 10 [2] 89 12 [2] ce 03 [2] 80 0f [2] 8c 05 [2] 9b 0e [2] 80 40 [2] bd }

  condition:
    any of them
}