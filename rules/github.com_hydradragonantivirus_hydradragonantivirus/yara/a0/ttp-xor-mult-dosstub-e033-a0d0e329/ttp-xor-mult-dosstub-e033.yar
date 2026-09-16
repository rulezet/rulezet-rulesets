rule TTP_XOR_MULT_DOSStub_e033 {
  strings:
    $key_e033 = { b4 5b [2] c0 43 [2] 87 41 [2] c0 50 [2] 8e 5c [2] 82 56 [2] 95 5d [2] 8e 13 [2] b3 }

  condition:
    any of them
}