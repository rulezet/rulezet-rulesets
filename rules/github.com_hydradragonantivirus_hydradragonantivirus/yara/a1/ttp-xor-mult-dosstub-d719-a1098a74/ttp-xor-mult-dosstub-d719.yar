rule TTP_XOR_MULT_DOSStub_d719 {
  strings:
    $key_d719 = { 83 71 [2] f7 69 [2] b0 6b [2] f7 7a [2] b9 76 [2] b5 7c [2] a2 77 [2] b9 39 [2] 84 }

  condition:
    any of them
}