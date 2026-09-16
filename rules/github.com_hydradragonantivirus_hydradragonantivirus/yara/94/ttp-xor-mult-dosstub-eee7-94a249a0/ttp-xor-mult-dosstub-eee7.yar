rule TTP_XOR_MULT_DOSStub_eee7 {
  strings:
    $key_eee7 = { ba 8f [2] ce 97 [2] 89 95 [2] ce 84 [2] 80 88 [2] 8c 82 [2] 9b 89 [2] 80 c7 [2] bd }

  condition:
    any of them
}