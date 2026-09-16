rule TTP_XOR_MULT_DOSStub_ee51 {
  strings:
    $key_ee51 = { ba 39 [2] ce 21 [2] 89 23 [2] ce 32 [2] 80 3e [2] 8c 34 [2] 9b 3f [2] 80 71 [2] bd }

  condition:
    any of them
}