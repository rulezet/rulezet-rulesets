rule TTP_XOR_MULT_DOSStub_ee6b {
  strings:
    $key_ee6b = { ba 03 [2] ce 1b [2] 89 19 [2] ce 08 [2] 80 04 [2] 8c 0e [2] 9b 05 [2] 80 4b [2] bd }

  condition:
    any of them
}