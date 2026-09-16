rule TTP_XOR_MULT_DOSStub_1112 {
  strings:
    $key_1112 = { 45 7a [2] 31 62 [2] 76 60 [2] 31 71 [2] 7f 7d [2] 73 77 [2] 64 7c [2] 7f 32 [2] 42 }

  condition:
    any of them
}