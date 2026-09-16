rule TTP_XOR_MULT_DOSStub_3c14 {
  strings:
    $key_3c14 = { 68 7c [2] 1c 64 [2] 5b 66 [2] 1c 77 [2] 52 7b [2] 5e 71 [2] 49 7a [2] 52 34 [2] 6f }

  condition:
    any of them
}