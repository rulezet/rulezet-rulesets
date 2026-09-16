rule TTP_XOR_MULT_DOSStub_ee5e {
  strings:
    $key_ee5e = { ba 36 [2] ce 2e [2] 89 2c [2] ce 3d [2] 80 31 [2] 8c 3b [2] 9b 30 [2] 80 7e [2] bd }

  condition:
    any of them
}