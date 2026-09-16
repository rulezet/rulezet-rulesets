rule TTP_XOR_MULT_DOSStub_ff95 {
  strings:
    $key_ff95 = { ab fd [2] df e5 [2] 98 e7 [2] df f6 [2] 91 fa [2] 9d f0 [2] 8a fb [2] 91 b5 [2] ac }

  condition:
    any of them
}