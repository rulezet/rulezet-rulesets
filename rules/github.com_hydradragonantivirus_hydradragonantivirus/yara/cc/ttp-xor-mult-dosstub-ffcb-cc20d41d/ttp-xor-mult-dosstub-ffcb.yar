rule TTP_XOR_MULT_DOSStub_ffcb {
  strings:
    $key_ffcb = { ab a3 [2] df bb [2] 98 b9 [2] df a8 [2] 91 a4 [2] 9d ae [2] 8a a5 [2] 91 eb [2] ac }

  condition:
    any of them
}