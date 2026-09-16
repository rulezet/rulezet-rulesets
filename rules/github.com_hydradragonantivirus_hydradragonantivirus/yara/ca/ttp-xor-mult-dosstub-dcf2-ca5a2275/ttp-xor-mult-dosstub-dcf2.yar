rule TTP_XOR_MULT_DOSStub_dcf2 {
  strings:
    $key_dcf2 = { 88 9a [2] fc 82 [2] bb 80 [2] fc 91 [2] b2 9d [2] be 97 [2] a9 9c [2] b2 d2 [2] 8f }

  condition:
    any of them
}