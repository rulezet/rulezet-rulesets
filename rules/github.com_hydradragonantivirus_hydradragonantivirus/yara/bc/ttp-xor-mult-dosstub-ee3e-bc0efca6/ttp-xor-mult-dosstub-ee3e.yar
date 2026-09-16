rule TTP_XOR_MULT_DOSStub_ee3e {
  strings:
    $key_ee3e = { ba 56 [2] ce 4e [2] 89 4c [2] ce 5d [2] 80 51 [2] 8c 5b [2] 9b 50 [2] 80 1e [2] bd }

  condition:
    any of them
}