rule TTP_XOR_MULT_DOSStub_ca78 {
  strings:
    $key_ca78 = { 9e 10 [2] ea 08 [2] ad 0a [2] ea 1b [2] a4 17 [2] a8 1d [2] bf 16 [2] a4 58 [2] 99 }

  condition:
    any of them
}