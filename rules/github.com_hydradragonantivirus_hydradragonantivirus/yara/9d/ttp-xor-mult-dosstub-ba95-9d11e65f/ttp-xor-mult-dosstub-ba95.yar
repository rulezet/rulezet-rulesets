rule TTP_XOR_MULT_DOSStub_ba95 {
  strings:
    $key_ba95 = { ee fd [2] 9a e5 [2] dd e7 [2] 9a f6 [2] d4 fa [2] d8 f0 [2] cf fb [2] d4 b5 [2] e9 }

  condition:
    any of them
}