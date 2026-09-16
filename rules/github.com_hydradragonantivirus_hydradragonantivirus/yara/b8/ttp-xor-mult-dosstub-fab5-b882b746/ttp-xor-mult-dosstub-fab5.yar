rule TTP_XOR_MULT_DOSStub_fab5 {
  strings:
    $key_fab5 = { ae dd [2] da c5 [2] 9d c7 [2] da d6 [2] 94 da [2] 98 d0 [2] 8f db [2] 94 95 [2] a9 }

  condition:
    any of them
}