rule TTP_XOR_MULT_DOSStub_b603 {
  strings:
    $key_b603 = { e2 6b [2] 96 73 [2] d1 71 [2] 96 60 [2] d8 6c [2] d4 66 [2] c3 6d [2] d8 23 [2] e5 }

  condition:
    any of them
}