rule TTP_XOR_MULT_DOSStub_ee1b {
  strings:
    $key_ee1b = { ba 73 [2] ce 6b [2] 89 69 [2] ce 78 [2] 80 74 [2] 8c 7e [2] 9b 75 [2] 80 3b [2] bd }

  condition:
    any of them
}