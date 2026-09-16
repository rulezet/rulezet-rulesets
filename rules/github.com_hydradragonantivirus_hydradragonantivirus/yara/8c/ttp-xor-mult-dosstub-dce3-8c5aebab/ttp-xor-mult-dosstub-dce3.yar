rule TTP_XOR_MULT_DOSStub_dce3 {
  strings:
    $key_dce3 = { 88 8b [2] fc 93 [2] bb 91 [2] fc 80 [2] b2 8c [2] be 86 [2] a9 8d [2] b2 c3 [2] 8f }

  condition:
    any of them
}