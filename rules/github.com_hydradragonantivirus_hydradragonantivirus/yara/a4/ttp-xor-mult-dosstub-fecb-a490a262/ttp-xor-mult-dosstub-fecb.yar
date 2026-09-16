rule TTP_XOR_MULT_DOSStub_fecb {
  strings:
    $key_fecb = { aa a3 [2] de bb [2] 99 b9 [2] de a8 [2] 90 a4 [2] 9c ae [2] 8b a5 [2] 90 eb [2] ad }

  condition:
    any of them
}