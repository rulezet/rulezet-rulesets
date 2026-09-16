rule TTP_XOR_MULT_DOSStub_ee16 {
  strings:
    $key_ee16 = { ba 7e [2] ce 66 [2] 89 64 [2] ce 75 [2] 80 79 [2] 8c 73 [2] 9b 78 [2] 80 36 [2] bd }

  condition:
    any of them
}