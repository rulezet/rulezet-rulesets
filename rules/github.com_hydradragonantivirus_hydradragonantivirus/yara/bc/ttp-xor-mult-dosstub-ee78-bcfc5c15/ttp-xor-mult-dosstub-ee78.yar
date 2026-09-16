rule TTP_XOR_MULT_DOSStub_ee78 {
  strings:
    $key_ee78 = { ba 10 [2] ce 08 [2] 89 0a [2] ce 1b [2] 80 17 [2] 8c 1d [2] 9b 16 [2] 80 58 [2] bd }

  condition:
    any of them
}