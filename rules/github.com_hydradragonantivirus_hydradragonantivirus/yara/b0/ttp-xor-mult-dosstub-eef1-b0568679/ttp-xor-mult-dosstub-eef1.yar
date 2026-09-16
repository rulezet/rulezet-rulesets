rule TTP_XOR_MULT_DOSStub_eef1 {
  strings:
    $key_eef1 = { ba 99 [2] ce 81 [2] 89 83 [2] ce 92 [2] 80 9e [2] 8c 94 [2] 9b 9f [2] 80 d1 [2] bd }

  condition:
    any of them
}