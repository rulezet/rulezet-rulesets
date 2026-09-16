rule TTP_XOR_MULT_DOSStub_ee7b {
  strings:
    $key_ee7b = { ba 13 [2] ce 0b [2] 89 09 [2] ce 18 [2] 80 14 [2] 8c 1e [2] 9b 15 [2] 80 5b [2] bd }

  condition:
    any of them
}