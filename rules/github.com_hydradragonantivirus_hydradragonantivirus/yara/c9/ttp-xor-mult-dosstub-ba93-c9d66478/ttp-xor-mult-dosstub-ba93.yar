rule TTP_XOR_MULT_DOSStub_ba93 {
  strings:
    $key_ba93 = { ee fb [2] 9a e3 [2] dd e1 [2] 9a f0 [2] d4 fc [2] d8 f6 [2] cf fd [2] d4 b3 [2] e9 }

  condition:
    any of them
}