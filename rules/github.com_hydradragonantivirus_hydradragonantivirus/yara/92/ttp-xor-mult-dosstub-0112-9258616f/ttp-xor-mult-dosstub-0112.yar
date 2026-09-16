rule TTP_XOR_MULT_DOSStub_0112 {
  strings:
    $key_0112 = { 55 7a [2] 21 62 [2] 66 60 [2] 21 71 [2] 6f 7d [2] 63 77 [2] 74 7c [2] 6f 32 [2] 52 }

  condition:
    any of them
}