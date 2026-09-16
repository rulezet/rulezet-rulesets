rule TTP_XOR_MULT_DOSStub_e573 {
  strings:
    $key_e573 = { b1 1b [2] c5 03 [2] 82 01 [2] c5 10 [2] 8b 1c [2] 87 16 [2] 90 1d [2] 8b 53 [2] b6 }

  condition:
    any of them
}