rule TTP_XOR_MULT_DOSStub_ee5c {
  strings:
    $key_ee5c = { ba 34 [2] ce 2c [2] 89 2e [2] ce 3f [2] 80 33 [2] 8c 39 [2] 9b 32 [2] 80 7c [2] bd }

  condition:
    any of them
}