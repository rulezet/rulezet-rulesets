rule TTP_XOR_MULT_DOSStub_ffca {
  strings:
    $key_ffca = { ab a2 [2] df ba [2] 98 b8 [2] df a9 [2] 91 a5 [2] 9d af [2] 8a a4 [2] 91 ea [2] ac }

  condition:
    any of them
}