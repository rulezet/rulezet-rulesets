rule TTP_XOR_MULT_DOSStub_3c05 {
  strings:
    $key_3c05 = { 68 6d [2] 1c 75 [2] 5b 77 [2] 1c 66 [2] 52 6a [2] 5e 60 [2] 49 6b [2] 52 25 [2] 6f }

  condition:
    any of them
}