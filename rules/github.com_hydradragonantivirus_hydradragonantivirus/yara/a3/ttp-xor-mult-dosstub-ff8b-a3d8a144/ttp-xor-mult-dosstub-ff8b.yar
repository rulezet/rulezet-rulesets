rule TTP_XOR_MULT_DOSStub_ff8b {
  strings:
    $key_ff8b = { ab e3 [2] df fb [2] 98 f9 [2] df e8 [2] 91 e4 [2] 9d ee [2] 8a e5 [2] 91 ab [2] ac }

  condition:
    any of them
}