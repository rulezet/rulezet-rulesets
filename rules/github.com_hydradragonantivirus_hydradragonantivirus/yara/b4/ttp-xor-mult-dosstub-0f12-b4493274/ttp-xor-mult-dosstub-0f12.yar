rule TTP_XOR_MULT_DOSStub_0f12 {
  strings:
    $key_0f12 = { 5b 7a [2] 2f 62 [2] 68 60 [2] 2f 71 [2] 61 7d [2] 6d 77 [2] 7a 7c [2] 61 32 [2] 5c }

  condition:
    any of them
}