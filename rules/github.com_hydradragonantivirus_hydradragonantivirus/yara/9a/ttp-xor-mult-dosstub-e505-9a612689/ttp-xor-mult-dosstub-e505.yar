rule TTP_XOR_MULT_DOSStub_e505 {
  strings:
    $key_e505 = { b1 6d [2] c5 75 [2] 82 77 [2] c5 66 [2] 8b 6a [2] 87 60 [2] 90 6b [2] 8b 25 [2] b6 }

  condition:
    any of them
}