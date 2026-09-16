rule TTP_XOR_MULT_DOSStub_c4bf {
  strings:
    $key_c4bf = { 90 d7 [2] e4 cf [2] a3 cd [2] e4 dc [2] aa d0 [2] a6 da [2] b1 d1 [2] aa 9f [2] 97 }

  condition:
    any of them
}