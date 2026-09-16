rule TTP_XOR_MULT_DOSStub_e439 {
  strings:
    $key_e439 = { b0 51 [2] c4 49 [2] 83 4b [2] c4 5a [2] 8a 56 [2] 86 5c [2] 91 57 [2] 8a 19 [2] b7 }

  condition:
    any of them
}