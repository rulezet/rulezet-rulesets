rule TTP_XOR_MULT_DOSStub_ee2e {
  strings:
    $key_ee2e = { ba 46 [2] ce 5e [2] 89 5c [2] ce 4d [2] 80 41 [2] 8c 4b [2] 9b 40 [2] 80 0e [2] bd }

  condition:
    any of them
}