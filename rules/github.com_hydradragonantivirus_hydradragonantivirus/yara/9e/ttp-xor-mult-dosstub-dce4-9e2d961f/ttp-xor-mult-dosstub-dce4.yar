rule TTP_XOR_MULT_DOSStub_dce4 {
  strings:
    $key_dce4 = { 88 8c [2] fc 94 [2] bb 96 [2] fc 87 [2] b2 8b [2] be 81 [2] a9 8a [2] b2 c4 [2] 8f }

  condition:
    any of them
}