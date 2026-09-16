rule TTP_XOR_MULT_DOSStub_ee61 {
  strings:
    $key_ee61 = { ba 09 [2] ce 11 [2] 89 13 [2] ce 02 [2] 80 0e [2] 8c 04 [2] 9b 0f [2] 80 41 [2] bd }

  condition:
    any of them
}