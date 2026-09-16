rule TTP_XOR_MULT_DOSStub_ee01 {
  strings:
    $key_ee01 = { ba 69 [2] ce 71 [2] 89 73 [2] ce 62 [2] 80 6e [2] 8c 64 [2] 9b 6f [2] 80 21 [2] bd }

  condition:
    any of them
}