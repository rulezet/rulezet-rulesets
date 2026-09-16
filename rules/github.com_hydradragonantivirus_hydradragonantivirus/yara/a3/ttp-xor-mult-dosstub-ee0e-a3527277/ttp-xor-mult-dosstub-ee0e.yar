rule TTP_XOR_MULT_DOSStub_ee0e {
  strings:
    $key_ee0e = { ba 66 [2] ce 7e [2] 89 7c [2] ce 6d [2] 80 61 [2] 8c 6b [2] 9b 60 [2] 80 2e [2] bd }

  condition:
    any of them
}