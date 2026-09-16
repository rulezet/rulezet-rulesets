rule TTP_XOR_MULT_DOSStub_eee1 {
  strings:
    $key_eee1 = { ba 89 [2] ce 91 [2] 89 93 [2] ce 82 [2] 80 8e [2] 8c 84 [2] 9b 8f [2] 80 c1 [2] bd }

  condition:
    any of them
}