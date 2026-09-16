rule TTP_XOR_MULT_DOSStub_6312 {
  strings:
    $key_6312 = { 37 7a [2] 43 62 [2] 04 60 [2] 43 71 [2] 0d 7d [2] 01 77 [2] 16 7c [2] 0d 32 [2] 30 }

  condition:
    any of them
}