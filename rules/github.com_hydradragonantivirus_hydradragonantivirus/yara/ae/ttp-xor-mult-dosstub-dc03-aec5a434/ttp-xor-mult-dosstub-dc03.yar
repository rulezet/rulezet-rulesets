rule TTP_XOR_MULT_DOSStub_dc03 {
  strings:
    $key_dc03 = { 88 6b [2] fc 73 [2] bb 71 [2] fc 60 [2] b2 6c [2] be 66 [2] a9 6d [2] b2 23 [2] 8f }

  condition:
    any of them
}