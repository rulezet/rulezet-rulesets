rule TTP_XOR_MULT_DOSStub_ee0b {
  strings:
    $key_ee0b = { ba 63 [2] ce 7b [2] 89 79 [2] ce 68 [2] 80 64 [2] 8c 6e [2] 9b 65 [2] 80 2b [2] bd }

  condition:
    any of them
}