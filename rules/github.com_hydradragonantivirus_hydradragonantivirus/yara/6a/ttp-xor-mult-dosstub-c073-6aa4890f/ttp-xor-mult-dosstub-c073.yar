rule TTP_XOR_MULT_DOSStub_c073 {
  strings:
    $key_c073 = { 94 1b [2] e0 03 [2] a7 01 [2] e0 10 [2] ae 1c [2] a2 16 [2] b5 1d [2] ae 53 [2] 93 }

  condition:
    any of them
}