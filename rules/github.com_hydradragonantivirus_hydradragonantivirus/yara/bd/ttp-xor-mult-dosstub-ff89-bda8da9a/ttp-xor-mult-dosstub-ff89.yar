rule TTP_XOR_MULT_DOSStub_ff89 {
  strings:
    $key_ff89 = { ab e1 [2] df f9 [2] 98 fb [2] df ea [2] 91 e6 [2] 9d ec [2] 8a e7 [2] 91 a9 [2] ac }

  condition:
    any of them
}