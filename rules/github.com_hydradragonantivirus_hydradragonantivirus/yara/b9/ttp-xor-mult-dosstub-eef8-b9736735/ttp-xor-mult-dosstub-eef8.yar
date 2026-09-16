rule TTP_XOR_MULT_DOSStub_eef8 {
  strings:
    $key_eef8 = { ba 90 [2] ce 88 [2] 89 8a [2] ce 9b [2] 80 97 [2] 8c 9d [2] 9b 96 [2] 80 d8 [2] bd }

  condition:
    any of them
}