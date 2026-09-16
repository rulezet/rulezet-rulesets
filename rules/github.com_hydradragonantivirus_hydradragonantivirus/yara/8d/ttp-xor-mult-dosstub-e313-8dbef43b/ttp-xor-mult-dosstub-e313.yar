rule TTP_XOR_MULT_DOSStub_e313 {
  strings:
    $key_e313 = { b7 7b [2] c3 63 [2] 84 61 [2] c3 70 [2] 8d 7c [2] 81 76 [2] 96 7d [2] 8d 33 [2] b0 }

  condition:
    any of them
}