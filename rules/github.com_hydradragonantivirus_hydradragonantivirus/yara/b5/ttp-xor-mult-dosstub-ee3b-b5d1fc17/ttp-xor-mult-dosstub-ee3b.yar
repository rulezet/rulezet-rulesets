rule TTP_XOR_MULT_DOSStub_ee3b {
  strings:
    $key_ee3b = { ba 53 [2] ce 4b [2] 89 49 [2] ce 58 [2] 80 54 [2] 8c 5e [2] 9b 55 [2] 80 1b [2] bd }

  condition:
    any of them
}