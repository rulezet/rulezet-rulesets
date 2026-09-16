rule TTP_XOR_MULT_DOSStub_c029 {
  strings:
    $key_c029 = { 94 41 [2] e0 59 [2] a7 5b [2] e0 4a [2] ae 46 [2] a2 4c [2] b5 47 [2] ae 09 [2] 93 }

  condition:
    any of them
}