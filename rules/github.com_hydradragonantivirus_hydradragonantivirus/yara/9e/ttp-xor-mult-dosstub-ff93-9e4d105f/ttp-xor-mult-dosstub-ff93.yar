rule TTP_XOR_MULT_DOSStub_ff93 {
  strings:
    $key_ff93 = { ab fb [2] df e3 [2] 98 e1 [2] df f0 [2] 91 fc [2] 9d f6 [2] 8a fd [2] 91 b3 [2] ac }

  condition:
    any of them
}