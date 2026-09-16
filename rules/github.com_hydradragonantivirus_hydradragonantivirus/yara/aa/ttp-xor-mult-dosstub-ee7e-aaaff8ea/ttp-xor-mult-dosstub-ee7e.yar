rule TTP_XOR_MULT_DOSStub_ee7e {
  strings:
    $key_ee7e = { ba 16 [2] ce 0e [2] 89 0c [2] ce 1d [2] 80 11 [2] 8c 1b [2] 9b 10 [2] 80 5e [2] bd }

  condition:
    any of them
}