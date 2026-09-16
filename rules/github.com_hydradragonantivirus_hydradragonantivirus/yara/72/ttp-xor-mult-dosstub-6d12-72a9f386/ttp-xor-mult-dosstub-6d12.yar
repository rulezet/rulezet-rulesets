rule TTP_XOR_MULT_DOSStub_6d12 {
  strings:
    $key_6d12 = { 39 7a [2] 4d 62 [2] 0a 60 [2] 4d 71 [2] 03 7d [2] 0f 77 [2] 18 7c [2] 03 32 [2] 3e }

  condition:
    any of them
}