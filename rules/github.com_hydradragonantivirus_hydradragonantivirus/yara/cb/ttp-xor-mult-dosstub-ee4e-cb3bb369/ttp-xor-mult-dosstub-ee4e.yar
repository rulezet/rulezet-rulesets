rule TTP_XOR_MULT_DOSStub_ee4e {
  strings:
    $key_ee4e = { ba 26 [2] ce 3e [2] 89 3c [2] ce 2d [2] 80 21 [2] 8c 2b [2] 9b 20 [2] 80 6e [2] bd }

  condition:
    any of them
}