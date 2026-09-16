rule TTP_XOR_MULT_DOSStub_c4ce {
  strings:
    $key_c4ce = { 90 a6 [2] e4 be [2] a3 bc [2] e4 ad [2] aa a1 [2] a6 ab [2] b1 a0 [2] aa ee [2] 97 }

  condition:
    any of them
}