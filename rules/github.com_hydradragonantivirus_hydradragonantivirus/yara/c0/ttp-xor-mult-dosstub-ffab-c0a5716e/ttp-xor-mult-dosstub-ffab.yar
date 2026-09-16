rule TTP_XOR_MULT_DOSStub_ffab {
  strings:
    $key_ffab = { ab c3 [2] df db [2] 98 d9 [2] df c8 [2] 91 c4 [2] 9d ce [2] 8a c5 [2] 91 8b [2] ac }

  condition:
    any of them
}